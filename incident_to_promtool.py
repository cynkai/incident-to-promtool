#!/usr/bin/env python3
"""Create and compare offline promtool rule tests from historical samples."""

import argparse
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import json
import math
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import subprocess
import sys
from tempfile import NamedTemporaryFile, TemporaryDirectory
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen
from xml.etree import ElementTree


EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
DURATION_PART = re.compile(r"(\d+)(ms|s|m|h|d)", re.ASCII)
UNIT_MS = {"ms": 1, "s": 1_000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}
METRIC_NAME = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
LABEL_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")
SELECTOR = re.compile(r'(?:[a-zA-Z_:][a-zA-Z0-9_:]*)?(?:\{(?:[^{}"\\]|"(?:[^"\\]|\\.)*")*\})?')
FLOAT = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", re.ASCII)
ALERT_MISMATCH = re.compile(r"\A(?:[^\S\n]*name:[^\n]*\n)?[^\S\n]*alertname:[^\n]*\n[^\S\n]*exp:")
MAX_VALUES = 2_000_000


def duration_ms(value):
    if not isinstance(value, str):
        raise ValueError("durations must be strings such as '30s' or '2m30s'")
    matches = list(DURATION_PART.finditer(value))
    if not matches or "".join(match[0] for match in matches) != value:
        raise ValueError(f"invalid duration: {value!r}")
    return sum(int(match[1]) * UNIT_MS[match[2]] for match in matches)


def as_duration(milliseconds):
    if milliseconds % 1000 == 0:
        return f"{milliseconds // 1000}s"
    return f"{milliseconds}ms"


def timestamp_ms(value):
    if not isinstance(value, str):
        raise ValueError("start and end must be ISO 8601 timestamps with a timezone")
    instant = datetime.fromisoformat(value.removesuffix("Z") + "+00:00" if value.endswith("Z") else value)
    if instant.tzinfo is None or instant.microsecond % 1000:
        raise ValueError("timestamps require a timezone and at most millisecond precision")
    delta = instant - EPOCH
    return instant.astimezone(timezone.utc), (delta.days * 86_400 + delta.seconds) * 1000 + delta.microseconds // 1000


def string_map(value, option, check_names=False):
    if not isinstance(value, dict) or any(
        not isinstance(item, str) or (check_names and not LABEL_NAME.fullmatch(key))
        for key, item in value.items()
    ):
        raise ValueError(f"{option} must be a JSON object with valid names and string values")
    return value


def read_json(path):
    with path.open(encoding="utf-8") as source:
        return json.load(source, parse_float=Decimal)


def rule_test_cases(expectations, window, evaluation):
    if not isinstance(expectations, list) or not expectations:
        raise ValueError("expectations must contain at least one firing or silent checkpoint")
    tests = []
    checkpoints = set()
    for item in expectations:
        offset = duration_ms(item["at"])
        alertname = item["alertname"]
        if offset > window or offset % evaluation:
            raise ValueError("expectation times must be evaluation ticks within the capture window")
        if not isinstance(alertname, str) or not alertname.strip():
            raise ValueError("an expectation must name the alert rule")
        if (offset, alertname) in checkpoints:
            raise ValueError(f"duplicate expectation for {alertname} at {item['at']}")
        checkpoints.add((offset, alertname))
        if not isinstance(item["alerts"], list):
            raise ValueError("alerts must be a list (use [] for no firing alerts)")
        expected = [
            {
                "exp_labels": string_map(alert["labels"], "labels", check_names=True),
                "exp_annotations": string_map(alert.get("annotations", {}), "annotations"),
            }
            for alert in item["alerts"]
        ]
        tests.append({"eval_time": as_duration(offset), "alertname": alertname, "exp_alerts": expected})
    return tests


def fetch_matrix(base_url, selector, end, window):
    params = urlencode({"query": f"{selector}[{as_duration(window + 1)}]", "time": end.isoformat()})
    request = Request(f"{base_url}/api/v1/query?{params}", headers={"Accept": "application/json"})
    token = os.environ.get("PROMETHEUS_BEARER_TOKEN")
    if token:
        # urllib does not copy unredirected headers to a subsequent request.
        request.add_unredirected_header("Authorization", f"Bearer {token}")
    try:
        with urlopen(request, timeout=30) as response:
            return json.load(response, parse_float=Decimal)
    except HTTPError as exc:
        raise ValueError(f"Prometheus returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise ValueError(f"Prometheus request failed: {exc.reason}") from exc


def series_name(labels):
    labels = string_map(labels, "series labels", check_names=True)
    metric = labels.get("__name__", "")
    if not METRIC_NAME.fullmatch(metric):
        raise ValueError("matrix series must contain a standard Prometheus metric name")
    matchers = [
        f"{key}={json.dumps(value, ensure_ascii=False)}"
        for key, value in sorted(labels.items()) if key != "__name__"
    ]
    return metric + ("{" + ",".join(matchers) + "}" if matchers else "")


def collect_series(matrices, start, end, step, round_up):
    samples_by_series = {}
    largest_shift = 0
    for matrix in matrices:
        if matrix.get("status") != "success" or matrix.get("warnings"):
            raise ValueError("Prometheus capture failed or reported warnings")
        result = matrix["data"]
        if result["resultType"] != "matrix":
            raise ValueError("expected raw matrix data from /api/v1/query with a range selector")
        for series in result["result"]:
            name = series_name(series["metric"])
            if series.get("histograms"):
                raise ValueError("native histograms require a different fixture format")
            slots = samples_by_series.setdefault(name, {})
            for timestamp, value in series["values"]:
                milliseconds = Decimal(str(timestamp)) * 1000
                if not milliseconds.is_finite() or milliseconds != milliseconds.to_integral_value():
                    raise ValueError("sample timestamps must have millisecond precision")
                offset = int(milliseconds) - start
                if offset < 0 or offset > end - start:
                    continue
                slot, remainder = divmod(offset, step)
                if remainder:
                    if not round_up:
                        raise ValueError(
                            f"a sample is off the {as_duration(step)} grid; "
                            "choose a finer sample_interval or rerun with --round-up"
                        )
                    largest_shift = max(largest_shift, step - remainder)
                    slot += 1
                if not isinstance(value, str) or not FLOAT.fullmatch(value) or not math.isfinite(float(value)):
                    raise ValueError("only finite float samples are supported")
                if slot in slots:
                    previous_offset, previous_value = slots[slot]
                    if previous_offset != offset:
                        raise ValueError("multiple samples land in one fixture slot; choose a finer sample_interval")
                    if float(previous_value).hex() != float(value).hex():
                        raise ValueError(f"conflicting values for {name} at the same timestamp")
                    continue
                slots[slot] = (offset, value)

    active = {name: slots for name, slots in samples_by_series.items() if slots}
    if not active:
        raise ValueError("no float samples found in the capture window")
    if sum(max(slots) + 1 for slots in active.values()) > MAX_VALUES:
        raise ValueError("capture exceeds 2,000,000 fixture slots; narrow the window or selectors")

    records = []
    for name, slots in sorted(active.items()):
        values = []
        next_slot = 0
        for slot, (_, value) in sorted(slots.items()):
            missing = slot - next_slot
            if missing:
                values.append("_" if missing == 1 else f"_x{missing}")
            values.append(value)
            next_slot = slot + 1
        records.append({"series": name, "values": " ".join(values)})
    return records, largest_shift


def generate(args):
    config = read_json(args.config)
    start, begin_ms = timestamp_ms(config["start"])
    end, end_ms = timestamp_ms(config["end"])
    window = end_ms - begin_ms
    step = duration_ms(config["sample_interval"])
    evaluation = duration_ms(config["evaluation_interval"])
    if window <= 0 or step <= 0 or evaluation <= 0 or evaluation % step:
        raise ValueError("end must follow start and evaluation_interval must be a positive multiple of sample_interval")
    if args.round_up and window % step:
        raise ValueError("with --round-up, end must fall on the sample grid")

    tests = rule_test_cases(config["expectations"], window, evaluation)
    if args.rule_file:
        paths = args.rule_file
    else:
        rule_files = config["rule_files"]
        if not isinstance(rule_files, list) or not rule_files or not all(isinstance(path, str) for path in rule_files):
            raise ValueError("rule_files must contain paths relative to the config file")
        paths = [args.config.parent / path for path in rule_files]
    if any(not path.is_file() for path in paths):
        raise ValueError("every rule file must exist")
    rule_files = [os.path.relpath(path.resolve(), args.output.parent.resolve()) for path in paths]

    if args.matrix:
        matrices = (read_json(path) for path in args.matrix)
    else:
        base_url = args.prometheus_url.rstrip("/")
        url = urlsplit(base_url)
        if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("use an HTTP(S) Prometheus base URL without credentials, query, or fragment")
        selectors = config["selectors"]
        if not isinstance(selectors, list) or not selectors or any(
            not isinstance(selector, str) or not selector or not SELECTOR.fullmatch(selector)
            for selector in selectors
        ):
            raise ValueError("selectors must contain raw metric selectors, such as requests_total{job=\"api\"}")
        matrices = (fetch_matrix(base_url, selector, end, window) for selector in selectors)

    records, shift = collect_series(matrices, begin_ms, end_ms, step, args.round_up)
    fixture = {
        "rule_files": rule_files,
        "evaluation_interval": as_duration(evaluation),
        "tests": [{
            "start_timestamp": start.isoformat(),
            "interval": as_duration(step),
            "input_series": records,
            "alert_rule_test": tests,
        }],
    }
    # JSON syntax is also valid YAML, which lets promtool read it without a Python YAML dependency.
    document = json.dumps(fixture, ensure_ascii=False, indent=2) + "\n"
    temporary = NamedTemporaryFile("w", encoding="utf-8", dir=args.output.parent, delete=False)
    path = Path(temporary.name)
    try:
        with temporary:
            temporary.write(document)
        os.link(path, args.output)
    finally:
        path.unlink()
    return len(records), len(tests), shift


def git_output(repo, *args):
    result = subprocess.run(
        ["git", "--literal-pathspecs", "-C", str(repo), *args],
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(detail or f"git {args[0]} exited with {result.returncode}")
    return result.stdout


def resolve_commit(repo, ref):
    try:
        return git_output(repo, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}").decode("ascii").strip()
    except ValueError as exc:
        raise ValueError(f"cannot resolve Git ref {ref!r}: {exc}") from exc


def read_committed_rules(repo, revision, paths):
    rules = []
    for path in paths:
        entries = git_output(repo, "ls-tree", "--full-tree", "-z", revision, "--", path)
        metadata, _, name = entries.removesuffix(b"\0").partition(b"\t")
        if name != os.fsencode(path):
            raise ValueError(f"rule path {path!r} was not found at Git commit {revision}")
        mode, kind, object_id = metadata.decode("ascii").split()
        if kind != "blob" or mode not in ("100644", "100755"):
            raise ValueError(f"rule path {path!r} is not a regular file at Git commit {revision}")
        rules.append(git_output(repo, "cat-file", "blob", object_id))
    return rules


def test_rule_version(promtool, fixture, rules, directory):
    directory.mkdir()
    rule_files = []
    for index, content in enumerate(rules, start=1):
        filename = f"rules-{index}.yml"
        (directory / filename).write_bytes(content)
        rule_files.append(filename)
    test_path = directory / "incident.test.yml"
    test_path.write_text(json.dumps({**fixture, "rule_files": rule_files}, ensure_ascii=False), encoding="utf-8")
    junit_path = directory / "results.xml"
    result = subprocess.run(
        [promtool, "test", "rules", f"--junit={junit_path}", str(test_path)],
        capture_output=True, encoding="utf-8", errors="replace", check=False,
    )
    try:
        report = ElementTree.parse(junit_path).getroot()
    except (ElementTree.ParseError, OSError):
        report = None
    if report is not None and report.tag == "testsuites":
        cases = report.findall("./testsuite/testcase")
        failures = [node.text or "" for node in report.findall(".//failure")]
        if len(cases) == len(fixture["tests"]) and not report.findall(".//error") and not report.findall(".//skipped"):
            if result.returncode == 0 and not failures:
                return []
            # Promtool uses exit 1 for both failed assertions and evaluation errors.
            # Alert expectation mismatches have distinct expected/actual diagnostics.
            if result.returncode == 1 and failures and all(ALERT_MISMATCH.match(item) for item in failures):
                return failures
    details = result.stderr.strip() or result.stdout.strip() or f"no usable JUnit results (exit {result.returncode})"
    raise ValueError(f"{directory.name} rules could not be tested:\n{details}")


def compare(fixture_path, before, after, executable, revisions=None):
    try:
        fixture = read_json(fixture_path)
    except json.JSONDecodeError as exc:
        raise ValueError("compare requires a JSON-formatted fixture generated by this CLI") from exc
    groups = fixture.get("tests") if isinstance(fixture, dict) else None
    if not isinstance(groups, list) or not groups or any(
        not isinstance(group, dict)
        or not isinstance(group.get("alert_rule_test"), list)
        or not group["alert_rule_test"]
        or group.get("promql_expr_test")
        for group in groups
    ):
        raise ValueError("compare requires a generated fixture with alert checkpoints in every test group")
    count = sum(len(group["alert_rule_test"]) for group in groups)
    promtool = shutil.which(executable)
    if not promtool:
        raise ValueError(f"promtool executable not found: {executable}")

    with TemporaryDirectory() as temporary:
        path = Path(temporary)
        before_failures = test_rule_version(promtool, fixture, before, path / "before")
        after_failures = test_rule_version(promtool, fixture, after, path / "after")

    print("## Prometheus alert comparison\n")
    if revisions:
        print(f"Compared Git commits `{revisions[0]}` and `{revisions[1]}` (before and after).\n")
    print("| Rule version | Result | Checkpoints matched |\n| --- | --- | ---: |")
    for version, failures in (("Before", before_failures), ("After", after_failures)):
        print(f"| {version} | {'Failed' if failures else 'Passed'} | {count - len(failures)}/{count} |")
    for version, failures in (("Before", before_failures), ("After", after_failures)):
        if failures:
            details = "\n\n".join(item.strip("\n") for item in failures)
            longest = max((len(run) for run in re.findall(r"`+", details)), default=0)
            fence = "`" * max(3, longest + 1)
            print(f"\n### {version} mismatches\n\n{fence}text\n{details}\n{fence}")
    return int(bool(after_failures))


def compare_main(argv):
    parser = argparse.ArgumentParser(
        prog=f"{Path(sys.argv[0]).name} compare",
        description="Compare two rulesets against identical captured samples and alert expectations.",
    )
    parser.add_argument("fixture", type=Path, help="a test fixture generated by this CLI")
    parser.add_argument("--before", type=Path, action="append", help="baseline rule file (repeatable)")
    parser.add_argument("--after", type=Path, action="append", help="proposed rule file (repeatable)")
    parser.add_argument("--before-ref", help="baseline Git ref or commit")
    parser.add_argument("--after-ref", help="proposed Git ref or commit")
    parser.add_argument("--rule-file", action="append", help="repository-root-relative path present in both commits (repeatable)")
    parser.add_argument("--repo", type=Path, help="Git repository for ref comparison (default: current directory)")
    parser.add_argument("--promtool", default="promtool", help="promtool executable or path")
    args = parser.parse_args(argv)
    git_mode = any(value is not None for value in (args.before_ref, args.after_ref, args.rule_file, args.repo))
    if git_mode and (args.before or args.after):
        parser.error("choose either --before and --after or Git ref comparison options")
    if git_mode and not (args.before_ref and args.after_ref and args.rule_file):
        parser.error("Git comparison requires --before-ref, --after-ref and at least one --rule-file")
    if not git_mode and not (args.before and args.after):
        parser.error("file comparison requires both --before and --after")
    try:
        if git_mode:
            for path in args.rule_file:
                if "\\" in path or PureWindowsPath(path).drive or any(part in ("", ".", "..") for part in path.split("/")):
                    raise ValueError(f"rule path {path!r} must be relative to the repository root and use '/' separators")
            repo = args.repo or Path.cwd()
            revisions = (resolve_commit(repo, args.before_ref), resolve_commit(repo, args.after_ref))
            before = read_committed_rules(repo, revisions[0], args.rule_file)
            after = read_committed_rules(repo, revisions[1], args.rule_file)
            return compare(args.fixture, before, after, args.promtool, revisions)
        before = [path.read_bytes() for path in args.before]
        after = [path.read_bytes() for path in args.after]
        return compare(args.fixture, before, after, args.promtool)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"error: {exc}\n")


def main():
    if sys.argv[1:2] == ["compare"]:
        return compare_main(sys.argv[2:])
    parser = argparse.ArgumentParser(
        description=__doc__, epilog="To compare two rulesets, run incident_to_promtool.py compare --help."
    )
    parser.add_argument("config", type=Path, help="incident window and expected alert states (JSON)")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--prometheus-url", help="query a Prometheus server for raw historical samples")
    source.add_argument("--matrix", type=Path, action="append", help="read a saved raw query response (repeatable)")
    parser.add_argument("--rule-file", type=Path, action="append", help="override config rule_files (repeatable)")
    parser.add_argument("--round-up", action="store_true", help="shift off-grid samples to the next fixture slot")
    parser.add_argument("--output", required=True, type=Path, help="new promtool YAML test file")
    args = parser.parse_args()
    try:
        series, checks, shift = generate(args)
    except FileExistsError:
        parser.exit(1, f"error: output file already exists: {args.output}\n")
    except (ValueError, KeyError, TypeError, AttributeError, InvalidOperation, OSError) as exc:
        parser.exit(1, f"error: {exc}\n")
    print(f"Wrote {args.output} ({series} series, {checks} checkpoints).")
    if shift:
        print(f"Shifted off-grid samples forward by up to {shift} ms.", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
