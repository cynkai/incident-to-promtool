#!/usr/bin/env python3
"""Create and compare offline promtool rule tests from historical samples."""

import argparse
from contextlib import suppress
from dataclasses import dataclass
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
DURATION_PART = re.compile(r"(\d+)(ms|s|m|h|d|w|y)", re.ASCII)
UNIT_MS = {"ms": 1, "s": 1_000, "m": 60_000, "h": 3_600_000, "d": 86_400_000,
           "w": 7 * 86_400_000, "y": 365 * 86_400_000}
METRIC_NAME = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
LABEL_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")
SELECTOR = re.compile(r'(?:[a-zA-Z_:][a-zA-Z0-9_:]*)?(?:\{(?:[^{}"\\]|"(?:[^"\\]|\\.)*")*\})?')
FLOAT = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", re.ASCII)
ALERT_MISMATCH = re.compile(r"\A[ \t]*alertname: (.+), time: ([^,\n]+),[ \t]*\n[ \t]*exp:")
MAX_VALUES = 2_000_000
MAX_PROMTOOL_DURATION_MS = (2**63 - 1) // 1_000_000


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


def write_new_json(path, data):
    document = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    temporary = NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False)
    staged = Path(temporary.name)
    try:
        with temporary:
            temporary.write(document)
        os.link(staged, path)
    finally:
        staged.unlink()


def read_rule_sources(paths):
    return [(str(path), path.read_bytes()) for path in paths]


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


def capture_samples(matrices, start, end):
    samples_by_series = {}
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
            samples = samples_by_series.setdefault(name, {})
            for timestamp, value in series["values"]:
                milliseconds = Decimal(str(timestamp)) * 1000
                if not milliseconds.is_finite() or milliseconds != milliseconds.to_integral_value():
                    raise ValueError("sample timestamps must have millisecond precision")
                offset = int(milliseconds) - start
                if offset < 0 or offset > end - start:
                    continue
                if not isinstance(value, str) or not FLOAT.fullmatch(value) or not math.isfinite(float(value)):
                    raise ValueError("only finite float samples are supported")
                if offset in samples:
                    if float(samples[offset]).hex() != float(value).hex():
                        raise ValueError(f"conflicting values for {name} at the same timestamp")
                    continue
                samples[offset] = value

    active = {name: samples for name, samples in samples_by_series.items() if samples}
    if not active:
        raise ValueError("no float samples found in the capture window")
    return active


def infer_sample_interval(samples_by_series, evaluation):
    step = evaluation
    for samples in samples_by_series.values():
        for offset in samples:
            step = math.gcd(step, offset)
            if step == 1:
                return step
    return step


def ceil_div(numerator, denominator):
    return (numerator + denominator - 1) // denominator


def slots_fit_shift(offsets, step, max_shift):
    previous_slot = -1
    for offset in offsets:
        slot = ceil_div(offset, step)
        if slot == previous_slot or slot * step - offset > max_shift:
            return False
        previous_slot = slot
    return True


def bounded_sample_interval(samples_by_series, evaluation, window, exact_step, max_shift):
    remaining_slots = MAX_VALUES - len(samples_by_series)
    if remaining_slots <= 0 or sum(map(len, samples_by_series.values())) > MAX_VALUES:
        return None
    offsets_by_series = [sorted(samples) for samples in samples_by_series.values()]
    last_offsets = [offsets[-1] for offsets in offsets_by_series]
    # The sum of rounded end slots cannot be smaller than sum(offsets) / step.
    smallest = max(exact_step + 1, ceil_div(sum(last_offsets), remaining_slots))
    if smallest > window:
        return None

    candidates = []
    for divisor in range(1, min(window, math.isqrt(evaluation)) + 1):
        complement, remainder = divmod(evaluation, divisor)
        if remainder == 0:
            if smallest <= divisor <= window:
                candidates.append(divisor)
            if complement != divisor and smallest <= complement <= window:
                candidates.append(complement)

    latest = max(last_offsets)
    for step in sorted(candidates):
        if ceil_div(latest, step) * step > window:
            continue
        if sum(ceil_div(last, step) for last in last_offsets) > remaining_slots:
            continue
        if all(slots_fit_shift(offsets, step, max_shift) for offsets in offsets_by_series):
            return step
    return None


def encode_samples(samples_by_series, step, round_up):
    records = []
    largest_shift = 0
    expanded_slots = 0
    for name, samples in sorted(samples_by_series.items()):
        values = []
        next_slot = 0
        for offset, value in sorted(samples.items()):
            slot = ceil_div(offset, step)
            delay = slot * step - offset
            if delay:
                if not round_up:
                    raise ValueError(
                        f"a sample is off the {as_duration(step)} grid; "
                        'set sample_interval to "auto", choose a finer interval, or rerun with --round-up'
                    )
                largest_shift = max(largest_shift, delay)
            missing = slot - next_slot
            if missing < 0:
                raise ValueError("multiple samples land in one fixture slot; choose a finer sample_interval")
            if missing:
                values.append("_" if missing == 1 else f"_x{missing}")
            values.append(value)
            next_slot = slot + 1
        expanded_slots += next_slot
        if expanded_slots > MAX_VALUES:
            raise ValueError(f"capture exceeds {MAX_VALUES:,} fixture slots; narrow the window or selectors")
        records.append({"series": name, "values": " ".join(values)})
    return records, largest_shift


def collect_series(matrices, start, end, step, round_up):
    return encode_samples(capture_samples(matrices, start, end), step, round_up)


def encode_automatic_samples(samples, evaluation, window, max_shift):
    exact_step = infer_sample_interval(samples, evaluation)
    step = exact_step
    exact_slots = sum(max(series) // exact_step + 1 for series in samples.values())
    if exact_slots > MAX_VALUES:
        if not max_shift:
            raise ValueError(
                f"automatic {as_duration(exact_step)} sample interval exceeds {MAX_VALUES:,} fixture slots; "
                "use a shorter capture window, narrow the selectors, or allow bounded rounding with --max-shift"
            )
        step = bounded_sample_interval(samples, evaluation, window, exact_step, max_shift)
        if step is None:
            raise ValueError(
                f"no automatic interval fits {MAX_VALUES:,} fixture slots with --max-shift {as_duration(max_shift)} "
                "while keeping distinct samples within the capture window; use a shorter window or narrower selectors"
            )
    records, shift = encode_samples(samples, step, round_up=step != exact_step)
    return records, shift, step


def generate(args):
    config = read_json(args.config)
    start, begin_ms = timestamp_ms(config["start"])
    end, end_ms = timestamp_ms(config["end"])
    window = end_ms - begin_ms
    evaluation = duration_ms(config["evaluation_interval"])
    automatic = config["sample_interval"] == "auto"
    step = evaluation if automatic else duration_ms(config["sample_interval"])
    if window <= 0 or step <= 0 or evaluation <= 0 or evaluation % step:
        raise ValueError("end must follow start and evaluation_interval must be a positive multiple of sample_interval")
    if evaluation > MAX_PROMTOOL_DURATION_MS:
        raise ValueError("evaluation_interval exceeds promtool's supported duration")
    if args.max_shift is not None and not automatic:
        raise ValueError('--max-shift requires sample_interval to be "auto"')
    max_shift = duration_ms(args.max_shift) if args.max_shift is not None else 0
    if args.round_up and not automatic and window % step:
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

    if automatic:
        samples = capture_samples(matrices, begin_ms, end_ms)
        records, shift, step = encode_automatic_samples(samples, evaluation, window, max_shift)
    else:
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
    write_new_json(args.output, fixture)
    return len(records), len(tests), shift, step if automatic else None


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
        rules.append((f"{revision}:{path}", git_output(repo, "cat-file", "blob", object_id)))
    return rules


@dataclass(frozen=True)
class ReplayFixture:
    path: Path
    data: dict
    checkpoint_keys: list[set[tuple[str, int]]]

    @property
    def checkpoints(self):
        return sum(map(len, self.checkpoint_keys))


def load_replay_fixture(path):
    try:
        data = read_json(path)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: compare requires a JSON-formatted fixture generated by this CLI") from exc
    groups = data.get("tests") if isinstance(data, dict) else None
    if not isinstance(groups, list) or not groups or any(
        not isinstance(group, dict)
        or not isinstance(group.get("alert_rule_test"), list)
        or not group["alert_rule_test"]
        or group.get("promql_expr_test")
        for group in groups
    ):
        raise ValueError(f"{path}: compare requires a generated fixture with alert checkpoints in every test group")
    checkpoint_keys = []
    for number, group in enumerate(groups, start=1):
        identities = set()
        for checkpoint in group["alert_rule_test"]:
            name = checkpoint.get("alertname") if isinstance(checkpoint, dict) else None
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f"{path}: alert checkpoint in group {number} requires an alertname")
            try:
                offset = duration_ms(checkpoint.get("eval_time", "0s"))
            except ValueError as exc:
                raise ValueError(f"{path}: alert {name!r} in group {number}: {exc}") from exc
            if (name, offset) in identities:
                raise ValueError(f"{path}: duplicate checkpoint for {name!r} in group {number} at {as_duration(offset)}")
            identities.add((name, offset))
        checkpoint_keys.append(identities)
    return ReplayFixture(path, data, checkpoint_keys)


def identify_alert_mismatches(fixture, cases):
    mismatches = {}
    for number, (case, group, known) in enumerate(
        zip(cases, fixture.data["tests"], fixture.checkpoint_keys), start=1,
    ):
        group_name = group.get("name", "")
        prefix = f"    name: {group_name},\n" if group_name else ""
        for failure in case.findall("./failure"):
            detail = failure.text or ""
            match = ALERT_MISMATCH.match(detail.removeprefix(prefix))
            if not match:
                raise ValueError(detail or "promtool reported an empty failure")
            name, time = match.groups()
            offset = duration_ms(time)
            identity = (number, name, offset)
            if (name, offset) not in known or identity in mismatches:
                raise ValueError(f"unexpected checkpoint failure in group {number}:\n{detail}")
            mismatches[identity] = detail
    return mismatches


def test_rule_version(promtool, fixtures, rules, directory):
    directory.mkdir()
    rule_files = []
    for index, content in enumerate(rules, start=1):
        filename = f"rules-{index}.yml"
        (directory / filename).write_bytes(content)
        rule_files.append(filename)
    test_paths = []
    for index, fixture in enumerate(fixtures, start=1):
        test_path = directory / f"incident-{index}.test.yml"
        try:
            document = json.dumps({**fixture.data, "rule_files": rule_files}, ensure_ascii=False)
        except TypeError as exc:
            raise ValueError(f"{fixture.path}: cannot stage fixture data: {exc}") from exc
        test_path.write_text(document, encoding="utf-8")
        test_paths.append(test_path)
    junit_path = directory / "results.xml"
    result = subprocess.run(
        [promtool, "test", "rules", f"--junit={junit_path}", *test_paths],
        capture_output=True, encoding="utf-8", errors="replace", check=False,
    )
    details = result.stderr.strip() or result.stdout.strip() or f"no usable JUnit results (exit {result.returncode})"
    for test_path, fixture in zip(test_paths, fixtures):
        details = details.replace(str(test_path), str(fixture.path))
    try:
        report = ElementTree.parse(junit_path).getroot()
    except (ElementTree.ParseError, OSError) as exc:
        raise ValueError(f"{directory.name} rules could not be tested:\n{details}") from exc
    suites = report.findall("./testsuite")
    if report.tag != "testsuites" or len(suites) != len(fixtures):
        raise ValueError(f"{directory.name} rules could not be tested:\n{details}")

    mismatches = []
    for suite, fixture, test_path in zip(suites, fixtures, test_paths):
        cases = suite.findall("./testcase")
        errors = [node.text or "" for node in suite.findall(".//error")]
        if (suite.get("name") != str(test_path) or len(cases) != len(fixture.data["tests"])
                or errors or suite.findall(".//skipped")):
            failures = [node.text or "" for node in suite.findall(".//failure")]
            diagnostics = "\n".join(errors + failures).strip() or details
            raise ValueError(f"{directory.name} rules could not be tested for {fixture.path}:\n{diagnostics}")
        # Only diagnostics that identify a known alert checkpoint are assertion mismatches.
        try:
            mismatches.append(identify_alert_mismatches(fixture, cases))
        except ValueError as exc:
            raise ValueError(f"{directory.name} rules could not be tested for {fixture.path}:\n{exc}") from exc
    if result.returncode != int(any(mismatches)):
        raise ValueError(f"{directory.name} rules could not be tested:\n{details}")
    return mismatches


def markdown_code(value):
    escaped = "".join(f"&#{ord(char)};" if char in "<>&|`\r\n[]*_\\~" else char for char in str(value))
    return f"<code>{escaped}</code>"


def build_comparison_report(fixtures, before_failures, after_failures, revisions, gate):
    count = sum(fixture.checkpoints for fixture in fixtures)
    summary = {
        "before": {"matched": count - sum(map(len, before_failures)), "total": count},
        "after": {"matched": count - sum(map(len, after_failures)), "total": count},
        "newly_failed": 0,
        "fixed": 0,
        "still_failing": 0,
    }
    fixture_results = []
    for fixture, baseline, candidate in zip(fixtures, before_failures, after_failures):
        changes = []
        for identity in sorted(baseline.keys() | candidate.keys()):
            group, name, offset = identity
            before_diagnostic = baseline.get(identity)
            after_diagnostic = candidate.get(identity)
            if before_diagnostic is None:
                change = "newly_failed"
            elif after_diagnostic is None:
                change = "fixed"
            else:
                change = "still_failing"
            summary[change] += 1
            changes.append({
                "group": group,
                "alertname": name,
                "offset_ms": offset,
                "change": change,
                "before_diagnostic": before_diagnostic,
                "after_diagnostic": after_diagnostic,
            })
        checks = fixture.checkpoints
        fixture_results.append({
            "path": str(fixture.path),
            "before": {"matched": checks - len(baseline), "total": checks},
            "after": {"matched": checks - len(candidate), "total": checks},
            "changes": changes,
        })
    gate_passed = summary["after"]["matched"] == count if gate == "strict" else summary["newly_failed"] == 0
    return {
        "schema_version": 1,
        "gate": {"mode": gate, "passed": gate_passed},
        "commits": {"before": revisions[0], "after": revisions[1]} if revisions else None,
        "summary": summary,
        "fixtures": fixture_results,
    }


def print_markdown_report(report):
    summary = report["summary"]
    fixtures = report["fixtures"]
    versions = ("before", "after")
    print("## Prometheus alert comparison\n")
    if commits := report["commits"]:
        print(f"Compared Git commits `{commits['before']}` and `{commits['after']}` (before and after).\n")
    gate = report["gate"]
    print(f"Gate `{gate['mode']}`: **{'Passed' if gate['passed'] else 'Failed'}**\n")
    print("| Rule version | Result | Checkpoints matched |\n| --- | --- | ---: |")
    for version in versions:
        matched, total = summary[version]["matched"], summary[version]["total"]
        print(f"| {version.title()} | {'Passed' if matched == total else 'Failed'} | {matched}/{total} |")
    if len(fixtures) > 1:
        print("\n| Incident fixture | Before | After |\n| --- | --- | --- |")
        for fixture in fixtures:
            cells = [markdown_code(fixture["path"])]
            for version in versions:
                matched, total = fixture[version]["matched"], fixture[version]["total"]
                cells.append(f"{'Passed' if matched == total else 'Failed'} ({matched}/{total})")
            print("| " + " | ".join(cells) + " |")
    if any(fixture["changes"] for fixture in fixtures):
        labels = {"newly_failed": "Newly failed", "fixed": "Fixed", "still_failing": "Still failing"}
        print("\n### Checkpoint changes\n")
        print("| Incident fixture | Group | Alert | Offset | Change |\n| --- | ---: | --- | --- | --- |")
        for fixture in fixtures:
            for change in fixture["changes"]:
                print(f"| {markdown_code(fixture['path'])} | {change['group']} | {markdown_code(change['alertname'])} "
                      f"| {as_duration(change['offset_ms'])} | {labels[change['change']]} |")
    for version in versions:
        if summary[version]["matched"] == summary[version]["total"]:
            continue
        print(f"\n### {version.title()} mismatches")
        for fixture in fixtures:
            key = f"{version}_diagnostic"
            failures = [item[key] for item in fixture["changes"] if item[key] is not None]
            if not failures:
                continue
            if len(fixtures) > 1:
                print(f"\n#### {markdown_code(fixture['path'])}")
            details = "\n\n".join(item.strip("\n") for item in failures)
            longest = max((len(run) for run in re.findall(r"`+", details)), default=0)
            fence = "`" * max(3, longest + 1)
            print(f"\n{fence}text\n{details}\n{fence}")


def compare(fixture_paths, before, after, executable, revisions=None, gate="strict", json_report=None):
    if len({os.path.realpath(path, strict=True) for path in fixture_paths}) != len(fixture_paths):
        raise ValueError("each incident fixture must be supplied only once")
    fixtures = [load_replay_fixture(path) for path in fixture_paths]
    promtool = shutil.which(executable)
    if not promtool:
        raise ValueError(f"promtool executable not found: {executable}")

    with TemporaryDirectory() as temporary:
        path = Path(temporary)
        before_failures = test_rule_version(promtool, fixtures, before, path / "before")
        after_failures = test_rule_version(promtool, fixtures, after, path / "after")

    report = build_comparison_report(fixtures, before_failures, after_failures, revisions, gate)
    if json_report is not None:
        try:
            write_new_json(json_report, report)
        except FileExistsError as exc:
            raise ValueError(f"JSON report already exists: {json_report}") from exc
    print_markdown_report(report)
    return int(not report["gate"]["passed"])


def compare_main(argv):
    parser = argparse.ArgumentParser(
        prog=f"{Path(sys.argv[0]).name} compare",
        description="Compare two rulesets against identical captured samples and alert expectations.",
    )
    parser.add_argument("fixtures", metavar="fixture", type=Path, nargs="+", help="test fixtures generated by this CLI")
    parser.add_argument("--before", type=Path, action="append", help="baseline rule file (repeatable)")
    parser.add_argument("--after", type=Path, action="append", help="proposed rule file (repeatable)")
    parser.add_argument("--before-ref", help="baseline Git ref or commit")
    parser.add_argument("--after-ref", help="proposed Git ref or commit")
    parser.add_argument("--rule-file", action="append", help="repository-root-relative path present in both commits (repeatable)")
    parser.add_argument("--repo", type=Path, help="Git repository for ref comparison (default: current directory)")
    parser.add_argument(
        "--rule-format", choices=("prometheus", "kubernetes"), default="prometheus",
        help="input rule format for both versions (default: prometheus)",
    )
    parser.add_argument("--promtool", default="promtool", help="promtool executable or path")
    parser.add_argument("--json-report", type=Path, help="also write a machine-readable report to this new path")
    parser.add_argument(
        "--gate", choices=("strict", "regressions"), default="strict",
        help="fail on any proposed mismatch or only on newly failing checkpoints (default: strict)",
    )
    args = parser.parse_args(argv)
    git_mode = any(value is not None for value in (args.before_ref, args.after_ref, args.rule_file, args.repo))
    if git_mode and (args.before or args.after):
        parser.error("choose either --before and --after or Git ref comparison options")
    if git_mode and not (args.before_ref and args.after_ref and args.rule_file):
        parser.error("Git comparison requires --before-ref, --after-ref and at least one --rule-file")
    if not git_mode and not (args.before and args.after):
        parser.error("file comparison requires both --before and --after")
    try:
        revisions = None
        if git_mode:
            for path in args.rule_file:
                if "\\" in path or PureWindowsPath(path).drive or any(part in ("", ".", "..") for part in path.split("/")):
                    raise ValueError(f"rule path {path!r} must be relative to the repository root and use '/' separators")
            repo = args.repo or Path.cwd()
            revisions = (resolve_commit(repo, args.before_ref), resolve_commit(repo, args.after_ref))
            before = read_committed_rules(repo, revisions[0], args.rule_file)
            after = read_committed_rules(repo, revisions[1], args.rule_file)
        else:
            before = read_rule_sources(args.before)
            after = read_rule_sources(args.after)
        if args.rule_format == "kubernetes":
            from kubernetes_rules import convert_manifests

            return compare(args.fixtures, convert_manifests(before), convert_manifests(after), args.promtool,
                           revisions, gate=args.gate, json_report=args.json_report)
        return compare(args.fixtures, [content for _, content in before], [content for _, content in after],
                       args.promtool, revisions, gate=args.gate, json_report=args.json_report)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"error: {exc}\n")


def export_rules_main(argv):
    parser = argparse.ArgumentParser(
        prog=f"{Path(sys.argv[0]).name} export-rules",
        description="Export rendered Kubernetes PrometheusRule manifests as native rule files.",
    )
    parser.add_argument("manifests", type=Path, nargs="+", help="rendered manifest files")
    parser.add_argument("--output-dir", required=True, type=Path, help="new directory for native rule files")
    args = parser.parse_args(argv)
    from kubernetes_rules import convert_manifests

    try:
        rules = convert_manifests(read_rule_sources(args.manifests))
        args.output_dir.mkdir()
        created = []
        try:
            for index, content in enumerate(rules, start=1):
                path = args.output_dir / f"rules-{index}.yml"
                with path.open("xb") as output:
                    created.append(path)
                    output.write(content)
        except BaseException:
            for path in created:
                with suppress(OSError):
                    path.unlink()
            with suppress(OSError):
                args.output_dir.rmdir()
            raise
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(f"Exported {len(rules)} native rule file(s) to {args.output_dir}.")


def main():
    if sys.argv[1:2] == ["compare"]:
        return compare_main(sys.argv[2:])
    if sys.argv[1:2] == ["export-rules"]:
        return export_rules_main(sys.argv[2:])
    parser = argparse.ArgumentParser(
        description=__doc__, epilog="See compare --help for rule comparisons or export-rules --help for Kubernetes manifests."
    )
    parser.add_argument("config", type=Path, help="incident window and expected alert states (JSON)")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--prometheus-url", help="query a Prometheus server for raw historical samples")
    source.add_argument("--matrix", type=Path, action="append", help="read a saved raw query response (repeatable)")
    parser.add_argument("--rule-file", type=Path, action="append", help="override config rule_files (repeatable)")
    parser.add_argument("--round-up", action="store_true", help="shift off-grid samples with a numeric sample interval")
    parser.add_argument("--max-shift", metavar="DURATION", help="allow bounded forward shifts if the exact auto grid is too large")
    parser.add_argument("--output", required=True, type=Path, help="new promtool YAML test file")
    args = parser.parse_args()
    try:
        series, checks, shift, automatic_interval = generate(args)
    except FileExistsError:
        parser.exit(1, f"error: output file already exists: {args.output}\n")
    except (ValueError, KeyError, TypeError, AttributeError, InvalidOperation, OSError) as exc:
        parser.exit(1, f"error: {exc}\n")
    print(f"Wrote {args.output} ({series} series, {checks} checkpoints).")
    if automatic_interval is not None:
        print(f"Automatically selected a {as_duration(automatic_interval)} sample interval.")
    if shift:
        print(f"Shifted off-grid samples forward by up to {shift} ms.", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
