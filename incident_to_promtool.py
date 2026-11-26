#!/usr/bin/env python3
"""Create and compare offline promtool rule tests from historical samples."""

import argparse
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import hashlib
from itertools import pairwise
import json
import math
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import stat
import subprocess
import sys
from tempfile import NamedTemporaryFile, TemporaryDirectory, TemporaryFile
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen
from xml.etree import ElementTree
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile
import zlib


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
BUNDLE_FIXTURE = "incident.test.yml"
BUNDLE_CAPTURE_SUMMARY = "capture.json"
BUNDLE_RULE_PATH = re.compile(r"rules/rules-[1-9][0-9]*\.yml")
BUNDLE_MANIFEST = "manifest.json"
BUNDLE_MANIFEST_VERSION = 1
BUNDLE_FIXED_FILES = (
    "incident.json", "incident.matrix.json", BUNDLE_FIXTURE, BUNDLE_CAPTURE_SUMMARY, "coverage.json",
)
SHA256_HEX = re.compile(r"[0-9a-fA-F]{64}")


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


def capture_window(config):
    start, begin_ms = timestamp_ms(config["start"])
    end, end_ms = timestamp_ms(config["end"])
    if end_ms <= begin_ms:
        raise ValueError("end must follow start")
    return (start, begin_ms), (end, end_ms)


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


@contextmanager
def new_output_file(path, mode, **options):
    temporary = NamedTemporaryFile(mode, dir=path.parent, delete=False, **options)
    staged = Path(temporary.name)
    try:
        with temporary:
            yield temporary
        os.link(staged, path)
    finally:
        staged.unlink()


def write_new_json(path, data):
    document = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    with new_output_file(path, "wb") as output:
        output.write(document)
    return document


def stream_sha256(source):
    digest = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def read_rule_sources(paths):
    return [(str(path), path.read_bytes()) for path in paths]


def webhook_test_alerts(item, config_dir):
    source = item["alertmanager_webhook"]
    if not isinstance(source, str) or not source.strip():
        raise ValueError("alertmanager_webhook must name a JSON file")
    path = config_dir / source
    try:
        webhook = read_json(path)
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read Alertmanager webhook {path}: {exc}") from exc
    if not isinstance(webhook, dict) or webhook.get("version") != "4":
        raise ValueError(f"{path}: expected an Alertmanager webhook with version '4'")
    truncated = webhook.get("truncatedAlerts", 0)
    if type(truncated) is not int or truncated < 0:
        raise ValueError(f"{path}: truncatedAlerts must be a nonnegative integer")
    if truncated:
        raise ValueError(f"{path}: Alertmanager webhook was truncated ({truncated} alerts omitted)")
    alerts = webhook.get("alerts")
    if not isinstance(alerts, list):
        raise ValueError(f"{path}: Alertmanager webhook requires an alerts array")

    drop_labels = item.get("drop_labels", [])
    if not isinstance(drop_labels, list) or any(
        not isinstance(label, str) or not LABEL_NAME.fullmatch(label) for label in drop_labels
    ):
        raise ValueError("drop_labels must be a list of valid label names")
    excluded = {"alertname", *drop_labels}
    alertname = item["alertname"]
    expected = {}
    for index, alert in enumerate(alerts, start=1):
        location = f"{path}: alert {index}"
        if not isinstance(alert, dict) or alert.get("status") not in ("firing", "resolved"):
            raise ValueError(f"{location} requires a firing or resolved status")
        labels = alert.get("labels")
        if not isinstance(labels, dict):
            raise ValueError(f"{location} requires a labels object")
        if labels.get("alertname") != alertname or alert["status"] != "firing":
            continue
        labels = string_map(
            {label: value for label, value in labels.items() if label not in excluded},
            f"{location} labels", check_names=True,
        )
        annotations = string_map(alert.get("annotations", {}), f"{location} annotations")
        identity = tuple(sorted(labels.items()))
        entry = {"exp_labels": labels, "exp_annotations": annotations}
        if expected.setdefault(identity, entry) != entry:
            raise ValueError(f"{location} has conflicting annotations for the same labels after import")
    if not expected:
        raise ValueError(f"{path}: no firing alerts named {alertname!r}")
    return list(expected.values())


def rule_test_cases(expectations, window, evaluation, config_dir):
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
        if "alertmanager_webhook" in item:
            if "alerts" in item:
                raise ValueError("each expectation must use either alerts or alertmanager_webhook")
            expected = webhook_test_alerts(item, config_dir)
        else:
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


def prometheus_json(base_url, endpoint, params, *, post=False):
    form = urlencode(params)
    url = f"{base_url}/api/v1/{endpoint}"
    request = Request(
        url if post else f"{url}?{form}", data=form.encode("ascii") if post else None,
        headers={"Accept": "application/json"},
    )
    token = os.environ.get("PROMETHEUS_BEARER_TOKEN")
    if token:
        # urllib does not copy unredirected headers to a subsequent request.
        request.add_unredirected_header("Authorization", f"Bearer {token}")
    try:
        with urlopen(request, timeout=30) as response:
            return json.load(response, parse_float=Decimal)
    except HTTPError as exc:
        message = f"Prometheus returned HTTP {exc.code} for /api/v1/{endpoint}"
        with exc, suppress(ValueError, OSError):
            error = json.loads(exc.read(4096))
            if isinstance(error, dict) and isinstance(error.get("error"), str):
                message += f": {error['error']}"
        raise ValueError(message) from exc
    except URLError as exc:
        raise ValueError(f"Prometheus request failed: {exc.reason}") from exc


def prometheus_base_url(value):
    base_url = value.rstrip("/")
    url = urlsplit(base_url)
    if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("use an HTTP(S) Prometheus base URL without credentials, query, or fragment")
    return base_url


def fetch_matrix(base_url, selector, end, window):
    params = {"query": f"{selector}[{as_duration(window + 1)}]", "time": end.isoformat()}
    return prometheus_json(base_url, "query", params)


def fetch_promql_ast(base_url, expression):
    response = prometheus_json(base_url, "parse_query", {"query": expression}, post=True)
    if not isinstance(response, dict) or response.get("status") != "success" or response.get("warnings"):
        raise ValueError("Prometheus could not parse the expression through /api/v1/parse_query")
    return response.get("data")


def capture_matrices(args, config, end, window):
    if args.matrix:
        return (read_json(path) for path in args.matrix)
    base_url = prometheus_base_url(args.prometheus_url)
    selectors = config["selectors"]
    if not isinstance(selectors, list) or not selectors or any(
        not isinstance(selector, str) or not selector or not SELECTOR.fullmatch(selector)
        for selector in selectors
    ):
        raise ValueError("selectors must contain raw metric selectors, such as requests_total{job=\"api\"}")
    return (fetch_matrix(base_url, selector, end, window) for selector in selectors)


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


@dataclass(frozen=True)
class CapturedSeries:
    labels: dict[str, str]
    samples: dict[int, str]


def capture_samples(matrices, start, end, *, allow_empty=False):
    samples_by_series = {}
    for matrix in matrices:
        if matrix.get("status") != "success" or matrix.get("warnings"):
            raise ValueError("Prometheus capture failed or reported warnings")
        result = matrix["data"]
        if result["resultType"] != "matrix":
            raise ValueError("expected raw matrix data from /api/v1/query with a range selector")
        for series in result["result"]:
            labels = series["metric"]
            name = series_name(labels)
            if series.get("histograms"):
                raise ValueError("native histograms require a different fixture format")
            samples = samples_by_series.setdefault(name, CapturedSeries(labels, {})).samples
            values = series["values"]
            if not isinstance(values, (list, tuple)):
                raise ValueError("matrix series values must be an array of samples")
            for sample in values:
                if not isinstance(sample, (list, tuple)) or len(sample) != 2:
                    raise ValueError("matrix samples must be timestamp and value pairs")
                timestamp, value = sample
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

    active = {name: series for name, series in samples_by_series.items() if series.samples}
    if not active and not allow_empty:
        raise ValueError("no float samples found in the capture window")
    return active


def infer_sample_interval(samples_by_series, evaluation):
    step = evaluation
    for series in samples_by_series.values():
        for offset in series.samples:
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
    if remaining_slots <= 0 or sum(len(series.samples) for series in samples_by_series.values()) > MAX_VALUES:
        return None
    offsets_by_series = [sorted(series.samples) for series in samples_by_series.values()]
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


@dataclass(frozen=True)
class EncodedSamples:
    series: list[dict[str, str]]
    sample_count: int
    shifted_sample_count: int
    max_shift_ms: int
    expanded_slots: int


def encode_samples(samples_by_series, step, round_up):
    records = []
    sample_count = 0
    shifted_sample_count = 0
    largest_shift = 0
    expanded_slots = 0
    for name, series in sorted(samples_by_series.items()):
        values = []
        next_slot = 0
        for offset, value in sorted(series.samples.items()):
            slot = ceil_div(offset, step)
            delay = slot * step - offset
            if delay:
                if not round_up:
                    raise ValueError(
                        f"a sample is off the {as_duration(step)} grid; "
                        'set sample_interval to "auto", choose a finer interval, or rerun with --round-up'
                    )
                largest_shift = max(largest_shift, delay)
                shifted_sample_count += 1
            missing = slot - next_slot
            if missing < 0:
                raise ValueError("multiple samples land in one fixture slot; choose a finer sample_interval")
            if missing:
                values.append("_" if missing == 1 else f"_x{missing}")
            values.append(value)
            next_slot = slot + 1
        sample_count += len(series.samples)
        expanded_slots += next_slot
        if expanded_slots > MAX_VALUES:
            raise ValueError(f"capture exceeds {MAX_VALUES:,} fixture slots; narrow the window or selectors")
        records.append({"series": name, "values": " ".join(values)})
    return EncodedSamples(records, sample_count, shifted_sample_count, largest_shift, expanded_slots)


def collect_series(matrices, start, end, step, round_up):
    capture = encode_samples(capture_samples(matrices, start, end), step, round_up)
    return capture.series, capture.max_shift_ms


def encode_automatic_samples(samples, evaluation, window, max_shift):
    exact_step = infer_sample_interval(samples, evaluation)
    step = exact_step
    exact_slots = sum(max(series.samples) // exact_step + 1 for series in samples.values())
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
    return encode_samples(samples, step, round_up=step != exact_step), step


def unix_seconds(milliseconds):
    # Write a JSON number directly from integer milliseconds.
    seconds, fraction = divmod(abs(milliseconds), 1000)
    sign = "-" if milliseconds < 0 else ""
    return f"{sign}{seconds}.{fraction:03d}"


def write_matrix_snapshot(path, samples, start_ms):
    with new_output_file(path, "w", encoding="utf-8", newline="\n") as output:
        output.write('{"status":"success","data":{"resultType":"matrix","result":[\n')
        for series_index, (_, series) in enumerate(sorted(samples.items())):
            if series_index:
                output.write(",\n")
            labels = json.dumps(series.labels, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            output.write(f'{{"metric":{labels},"values":[')
            for sample_index, (offset, value) in enumerate(sorted(series.samples.items())):
                if sample_index:
                    output.write(",")
                timestamp = unix_seconds(start_ms + offset)
                output.write(f"[{timestamp},{json.dumps(value)}]")
            output.write("]}")
        output.write("\n]}}\n")


@dataclass(frozen=True)
class PreparedCapture:
    fixture: dict
    summary: dict
    samples: dict[str, CapturedSeries]
    start: datetime
    end: datetime
    begin_ms: int


def capture_rule_paths(args, config):
    if args.rule_file:
        paths = args.rule_file
    else:
        rule_files = config["rule_files"]
        if not isinstance(rule_files, list) or not rule_files or not all(isinstance(path, str) for path in rule_files):
            raise ValueError("rule_files must contain paths relative to the config file")
        paths = [args.config.parent / path for path in rule_files]
    if any(not path.is_file() for path in paths):
        raise ValueError("every rule file must exist")
    return paths


def prepare_capture(args, config, rule_files):
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

    tests = rule_test_cases(config["expectations"], window, evaluation, args.config.parent)
    matrices = capture_matrices(args, config, end, window)
    samples = capture_samples(matrices, begin_ms, end_ms)
    if automatic:
        capture, step = encode_automatic_samples(samples, evaluation, window, max_shift)
        sampling_mode = "auto_bounded" if capture.shifted_sample_count else "auto_exact"
        shift_limit = max_shift if args.max_shift is not None else None
    else:
        capture = encode_samples(samples, step, args.round_up)
        sampling_mode = "fixed_round_up" if args.round_up else "fixed_exact"
        shift_limit = step - 1 if args.round_up else None
    fixture = {
        "rule_files": rule_files,
        "evaluation_interval": as_duration(evaluation),
        "tests": [{
            "start_timestamp": start.isoformat(),
            "interval": as_duration(step),
            "input_series": capture.series,
            "alert_rule_test": tests,
        }],
    }
    summary = {
        "start": start.isoformat(),
        "end": end.isoformat(),
        "evaluation_interval_ms": evaluation,
        "sample_interval_ms": step,
        "sampling_mode": sampling_mode,
        "max_shift_ms": capture.max_shift_ms,
        "max_shift_limit_ms": shift_limit,
        "series_count": len(capture.series),
        "sample_count": capture.sample_count,
        "shifted_sample_count": capture.shifted_sample_count,
        "checkpoint_count": len(tests),
        "expanded_slots": capture.expanded_slots,
    }
    return PreparedCapture(fixture, summary, samples, start, end, begin_ms)


def write_capture_fixture(path, prepared, *, relative=False):
    # JSON syntax is also valid YAML, which lets promtool read it without a Python YAML dependency.
    document = write_new_json(path, prepared.fixture)
    return {
        "schema_version": 1,
        "fixture_path": path.name if relative else str(path),
        "fixture_sha256": hashlib.sha256(document).hexdigest(),
        **prepared.summary,
    }


def generate(args):
    config = read_json(args.config)
    parent = args.output.parent.resolve()
    rule_files = [Path(os.path.relpath(path.resolve(), parent)).as_posix() for path in capture_rule_paths(args, config)]
    prepared = prepare_capture(args, config, rule_files)
    return write_capture_fixture(args.output, prepared)


def offline_incident_config(prepared, sample_interval):
    fixture = prepared.fixture
    return {
        "start": prepared.start.isoformat(),
        "end": prepared.end.isoformat(),
        "sample_interval": sample_interval,
        "evaluation_interval": fixture["evaluation_interval"],
        "rule_files": fixture["rule_files"],
        "expectations": [
            {
                "at": case["eval_time"],
                "alertname": case["alertname"],
                "alerts": [
                    {"labels": alert["exp_labels"], "annotations": alert["exp_annotations"]}
                    for alert in case["exp_alerts"]
                ],
            }
            for case in fixture["tests"][0]["alert_rule_test"]
        ],
    }


def write_bundle(args):
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError(args.output)
    config = read_json(args.config)
    rule_paths = list(dict.fromkeys(path.resolve() for path in capture_rule_paths(args, config)))
    rule_files = [f"rules/rules-{number}.yml" for number in range(1, len(rule_paths) + 1)]
    with TemporaryDirectory(prefix="incident-to-promtool-") as temporary:
        directory = Path(temporary)
        (directory / "rules").mkdir()
        for original, portable in zip(rule_paths, rule_files):
            (directory / portable).write_bytes(original.read_bytes())

        prepared = prepare_capture(args, config, rule_files)
        summary = write_capture_fixture(directory / BUNDLE_FIXTURE, prepared, relative=True)
        generation_options = ["--round-up"] if args.round_up else []
        if args.max_shift is not None:
            generation_options.extend(("--max-shift", args.max_shift))
        summary["generation_options"] = generation_options
        summary["bundle_manifest_version"] = BUNDLE_MANIFEST_VERSION
        write_new_json(directory / BUNDLE_CAPTURE_SUMMARY, summary)
        write_new_json(directory / "incident.json", offline_incident_config(prepared, config["sample_interval"]))
        write_matrix_snapshot(directory / "incident.matrix.json", prepared.samples, prepared.begin_ms)
        coverage = build_coverage_report(prepared.samples, prepared.start, prepared.end, None)
        write_new_json(directory / "coverage.json", coverage)

        entries = [*BUNDLE_FIXED_FILES, *rule_files]
        digests = {}
        for name in entries:
            with (directory / name).open("rb") as content:
                digests[name] = stream_sha256(content)
        write_new_json(directory / BUNDLE_MANIFEST, {"schema_version": BUNDLE_MANIFEST_VERSION, "files": digests})
        with new_output_file(args.output, "w+b") as output:
            with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
                for name in (*entries, BUNDLE_MANIFEST):
                    archive.write(directory / name, arcname=name)
    return summary


def git_output(repo, *args, stdout=subprocess.PIPE):
    result = subprocess.run(
        ["git", "--no-replace-objects", "--literal-pathspecs", "-C", str(repo), *args],
        stdout=stdout, stderr=subprocess.PIPE, check=False,
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


def committed_file_id(repo, revision, path, label):
    if "\\" in path or PureWindowsPath(path).drive or any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError(f"{label} path {path!r} must be relative to the repository root and use '/' separators")
    entries = git_output(repo, "ls-tree", "--full-tree", "-z", revision, "--", path)
    metadata, _, name = entries.removesuffix(b"\0").partition(b"\t")
    if name != os.fsencode(path):
        raise ValueError(f"{label} path {path!r} was not found at Git commit {revision}")
    mode, kind, object_id = metadata.decode("ascii").split()
    if kind != "blob" or mode not in ("100644", "100755"):
        raise ValueError(f"{label} path {path!r} is not a regular file at Git commit {revision}")
    return object_id


def read_committed_file(repo, revision, path, label):
    return git_output(repo, "cat-file", "blob", committed_file_id(repo, revision, path, label))


def read_committed_rules(repo, revision, paths):
    return [(f"{revision}:{path}", read_committed_file(repo, revision, path, "rule")) for path in paths]


@dataclass(frozen=True)
class ReplayFixture:
    path: Path | str
    data: dict
    checkpoint_keys: list[set[tuple[str, int]]]
    sha256: str | None
    capture_summary: Path | str | None

    @property
    def checkpoints(self):
        return sum(map(len, self.checkpoint_keys))


def load_replay_fixture(path, contents, checksum, capture_summary):
    try:
        data = json.loads(contents.decode("utf-8"), parse_float=Decimal)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
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
    return ReplayFixture(path, data, checkpoint_keys, checksum, capture_summary)


def read_replay_bytes(path, repo, commit, label):
    if commit is not None:
        return read_committed_file(repo, commit, path.as_posix(), label)
    return path.read_bytes()


def load_capture_summary(path, contents):
    try:
        summary = json.loads(contents.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"{path}: capture summary must contain valid JSON") from exc
    version = summary.get("schema_version") if isinstance(summary, dict) else None
    if type(version) is not int or version != 1:
        raise ValueError(f"{path}: capture summary requires schema_version 1")
    digest = summary.get("fixture_sha256")
    if not isinstance(digest, str) or not SHA256_HEX.fullmatch(digest):
        raise ValueError(f"{path}: capture summary requires a valid fixture_sha256 (64 hex digits)")
    return summary


def verify_capture_summary(path, checksum, summary, summary_bytes):
    data = load_capture_summary(summary, summary_bytes)
    if data["fixture_sha256"].lower() != checksum:
        raise ValueError(f"{path}: fixture SHA-256 does not match capture summary {summary}")
    return data


def load_replay_fixtures(paths, summaries, repo, commit):
    identities = {path.as_posix() if commit else os.path.realpath(path, strict=True) for path in paths}
    if len(identities) != len(paths):
        raise ValueError("each incident fixture must be supplied only once")
    fixtures = []
    for path, summary in zip(paths, summaries or [None] * len(paths)):
        contents = read_replay_bytes(path, repo, commit, "fixture")
        checksum = hashlib.sha256(contents).hexdigest() if commit or summary is not None else None
        if summary is not None:
            summary_bytes = read_replay_bytes(summary, repo, commit, "capture summary")
            verify_capture_summary(path, checksum, summary, summary_bytes)
        fixtures.append(load_replay_fixture(path, contents, checksum, summary))
    return fixtures


@contextmanager
def open_bundle_archive(path, source=None):
    try:
        with ZipFile(path if source is None else source) as archive:
            names = set(archive.namelist())
            if len(names) != len(archive.infolist()):
                raise ValueError(f"{path}: ZIP archive contains duplicate member names")
            yield archive, names
    except (BadZipFile, EOFError, RuntimeError, zlib.error) as exc:
        raise ValueError(f"{path}: could not read the incident bundle ZIP: {exc}") from exc


def bundle_member_info(archive, path, name):
    try:
        entry = archive.getinfo(name)
    except KeyError as exc:
        raise ValueError(f"{path}: missing ZIP member {name!r}") from exc
    kind = stat.S_IFMT(entry.external_attr >> 16) if entry.create_system == 3 else 0
    if entry.orig_filename != name or entry.is_dir() or entry.external_attr & 0x10 or kind not in (0, stat.S_IFREG):
        raise ValueError(f"{path}: ZIP member {name!r} must be a regular file")
    return entry


def verify_bundle_member_hash(path, name, checksum, manifest):
    if checksum != manifest[name]:
        raise ValueError(f"{path}!{name}: SHA-256 does not match {BUNDLE_MANIFEST}")


def read_bundle_member(archive, path, name, manifest=None):
    contents = archive.read(bundle_member_info(archive, path, name))
    if manifest is not None:
        verify_bundle_member_hash(path, name, hashlib.sha256(contents).hexdigest(), manifest)
    return contents


def unique_manifest_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def read_bundle_manifest(archive, path, names):
    if BUNDLE_MANIFEST not in names:
        return None
    contents = read_bundle_member(archive, path, BUNDLE_MANIFEST)
    try:
        document = json.loads(contents.decode("utf-8"), object_pairs_hook=unique_manifest_object)
    except (ValueError, RecursionError) as exc:
        raise ValueError(f"{path}!{BUNDLE_MANIFEST}: invalid manifest JSON: {exc}") from exc
    version = document.get("schema_version") if isinstance(document, dict) else None
    if type(version) is not int or version != BUNDLE_MANIFEST_VERSION:
        raise ValueError(f"{path}!{BUNDLE_MANIFEST}: unsupported manifest schema_version {version!r}")
    files = document.get("files")
    if not isinstance(files, dict):
        raise ValueError(f"{path}!{BUNDLE_MANIFEST}: files must map paths to SHA-256 digests")
    fixed = set(BUNDLE_FIXED_FILES)
    if missing := fixed - files.keys():
        raise ValueError(f"{path}!{BUNDLE_MANIFEST}: missing required files {', '.join(sorted(missing))}")
    rules = files.keys() - fixed
    if not rules or any(not BUNDLE_RULE_PATH.fullmatch(name) for name in rules):
        raise ValueError(f"{path}!{BUNDLE_MANIFEST}: expected valid bundled rule member paths")
    if missing := files.keys() - names:
        raise ValueError(f"{path}: missing ZIP members declared in {BUNDLE_MANIFEST}: {', '.join(sorted(missing))}")
    if extra := names - files.keys() - {BUNDLE_MANIFEST}:
        raise ValueError(f"{path}: undeclared ZIP members: {', '.join(sorted(extra))}")
    for name, digest in files.items():
        if not isinstance(digest, str) or not SHA256_HEX.fullmatch(digest):
            raise ValueError(f"{path}!{BUNDLE_MANIFEST}: invalid SHA-256 for {name!r}")
    return {name: digest.lower() for name, digest in files.items()}


def verify_bundle_capture_summary(path, checksum, contents, manifest):
    summary = verify_capture_summary(f"{path}!{BUNDLE_FIXTURE}", checksum, f"{path}!{BUNDLE_CAPTURE_SUMMARY}", contents)
    if "bundle_manifest_version" in summary:
        version = summary["bundle_manifest_version"]
        if type(version) is not int or version != BUNDLE_MANIFEST_VERSION:
            raise ValueError(f"{path}!{BUNDLE_CAPTURE_SUMMARY}: unsupported bundle_manifest_version {version!r}")
        if manifest is None:
            raise ValueError(f"{path}: capture summary requires {BUNDLE_MANIFEST}")


def load_bundle_replay(path, *, source=None):
    fixture_path = f"{path}!{BUNDLE_FIXTURE}"
    summary_path = f"{path}!{BUNDLE_CAPTURE_SUMMARY}"
    with open_bundle_archive(path, source) as (archive, names):
        manifest = read_bundle_manifest(archive, path, names)
        contents = read_bundle_member(archive, path, BUNDLE_FIXTURE, manifest)
        summary = read_bundle_member(archive, path, BUNDLE_CAPTURE_SUMMARY, manifest)
        checksum = manifest[BUNDLE_FIXTURE] if manifest is not None else hashlib.sha256(contents).hexdigest()
        verify_bundle_capture_summary(path, checksum, summary, manifest)
        fixture = load_replay_fixture(fixture_path, contents, checksum, summary_path)
        rule_paths = fixture.data.get("rule_files")
        if not isinstance(rule_paths, list) or not rule_paths or any(
            not isinstance(name, str) or not BUNDLE_RULE_PATH.fullmatch(name) for name in rule_paths
        ) or len(rule_paths) != len(set(rule_paths)):
            raise ValueError(f"{fixture_path}: rule_files must list distinct bundled paths such as 'rules/rules-1.yml'")
        rules = [read_bundle_member(archive, path, name, manifest) for name in rule_paths]
    return fixture, rules, {"path": str(path), "rule_files": rule_paths}


def verify_bundle(path):
    with open_bundle_archive(path) as (archive, names):
        manifest = read_bundle_manifest(archive, path, names)
        if manifest is None:
            raise ValueError(f"{path}: missing {BUNDLE_MANIFEST}; full verification requires a manifest")
        summary = read_bundle_member(archive, path, BUNDLE_CAPTURE_SUMMARY, manifest)
        verify_bundle_capture_summary(path, manifest[BUNDLE_FIXTURE], summary, manifest)
        for name in manifest:
            if name != BUNDLE_CAPTURE_SUMMARY:
                with archive.open(bundle_member_info(archive, path, name)) as content:
                    verify_bundle_member_hash(path, name, stream_sha256(content), manifest)
    return {"schema_version": 1, "bundle_path": str(path), "verified_files": sorted(manifest)}


def load_committed_bundle_replay(repo, revision, path):
    object_id = committed_file_id(repo, revision, path, "bundle")
    with TemporaryFile() as source:
        git_output(repo, "cat-file", "blob", object_id, stdout=source)
        source.seek(0)
        return load_bundle_replay(path, source=source)


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


def test_rule_version(promtool, fixtures, rule_sets, directory):
    directory.mkdir()
    staged_rules = {}
    next_rule = 1
    test_paths = []
    for index, (fixture, rules) in enumerate(zip(fixtures, rule_sets, strict=True), start=1):
        rules = tuple(rules)
        if rules not in staged_rules:
            rule_files = []
            for content in rules:
                filename = f"rules-{next_rule}.yml"
                (directory / filename).write_bytes(content)
                rule_files.append(filename)
                next_rule += 1
            staged_rules[rules] = rule_files
        test_path = directory / f"incident-{index}.test.yml"
        try:
            document = json.dumps({**fixture.data, "rule_files": staged_rules[rules]}, ensure_ascii=False)
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


def build_coverage_report(samples, start, end, max_gap_ms):
    window = (end - start) // timedelta(milliseconds=1)

    def timestamp_at(offset):
        return (start + timedelta(milliseconds=offset)).isoformat()

    details = []
    for name, series in sorted(samples.items()):
        offsets = sorted(series.samples)
        first, last = offsets[0], offsets[-1]
        largest = max(pairwise(offsets), key=lambda pair: pair[1] - pair[0], default=None)
        gap = None
        if largest is not None:
            left, right = largest
            gap = {"start": timestamp_at(left), "end": timestamp_at(right), "duration_ms": right - left}
        detail = {
            "series": name,
            "sample_count": len(offsets),
            "first_sample": timestamp_at(first),
            "last_sample": timestamp_at(last),
            "leading_gap_ms": first,
            "trailing_gap_ms": window - last,
            "max_sample_gap": gap,
        }
        if max_gap_ms is not None:
            detail["gap_exceeded"] = max(first, window - last, gap["duration_ms"] if gap else 0) > max_gap_ms
        details.append(detail)
    gate = None
    if max_gap_ms is not None:
        gate = {"max_gap_ms": max_gap_ms, "passed": bool(details) and not any(row["gap_exceeded"] for row in details)}
    return {
        "schema_version": 1,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "series_count": len(details),
        "sample_count": sum(row["sample_count"] for row in details),
        "series": details,
        "gate": gate,
    }


def print_coverage_report(report):
    print("## Prometheus sample coverage\n")
    print(f"Capture window `{report['start']}` to `{report['end']}`.\n")
    print(f"{report['series_count']} observed series, {report['sample_count']} samples.\n")
    gate = report["gate"]
    if gate is not None:
        result = "Passed" if gate["passed"] else "Failed"
        print(f"Gap limit `{as_duration(gate['max_gap_ms'])}` **{result}**.\n")
    if not report["series"]:
        print("No samples found in the capture window.")
        return
    columns = ["Series", "Samples", "First sample (UTC)", "Last sample (UTC)", "Start gap", "Longest sample gap", "End gap"]
    if gate is not None:
        columns.append("Gap check")
    print("| " + " | ".join(columns) + " |")
    print("| " + " | ".join(["---"] * len(columns)) + " |")
    for row in report["series"]:
        gap = row["max_sample_gap"]
        cells = [
            markdown_code(row["series"]), str(row["sample_count"]), row["first_sample"], row["last_sample"],
            as_duration(row["leading_gap_ms"]), as_duration(gap["duration_ms"]) if gap else "—",
            as_duration(row["trailing_gap_ms"]),
        ]
        if gate is not None:
            cells.append("Exceeded" if row["gap_exceeded"] else "Within limit")
        print("| " + " | ".join(cells) + " |")


def build_comparison_report(fixtures, before_failures, after_failures, revisions, gate, fixture_commit):
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
        result = {
            "path": str(fixture.path),
            "before": {"matched": checks - len(baseline), "total": checks},
            "after": {"matched": checks - len(candidate), "total": checks},
            "changes": changes,
        }
        if fixture.sha256 is not None:
            result["sha256"] = fixture.sha256
        if fixture.capture_summary is not None:
            result["capture_summary"] = str(fixture.capture_summary)
        fixture_results.append(result)
    gate_passed = summary["after"]["matched"] == count if gate == "strict" else summary["newly_failed"] == 0
    report = {
        "schema_version": 1,
        "gate": {"mode": gate, "passed": gate_passed},
        "commits": {"before": revisions[0], "after": revisions[1]} if revisions else None,
        "summary": summary,
        "fixtures": fixture_results,
    }
    if fixture_commit is not None:
        report["fixture_commit"] = fixture_commit
    return report


def print_markdown_report(report):
    summary = report["summary"]
    fixtures = report["fixtures"]
    versions = ("before", "after")
    print("## Prometheus alert comparison\n")
    commits = report["commits"]
    bundle = report.get("bundle")
    bundles = report.get("bundles")
    if bundle or bundles:
        anchor = f" at Git commit `{commits['before']}`" if commits else ""
        if bundle:
            print(f"Loaded the baseline rules and fixture from bundle {markdown_code(bundle['path'])}{anchor}.\n")
        else:
            print(f"Loaded baseline rules and fixtures from {len(bundles)} bundles{anchor}.\n")
        if commits:
            print(f"Read proposed rules from Git commit `{commits['after']}`.\n")
    elif commits:
        print(f"Compared Git commits `{commits['before']}` and `{commits['after']}` (before and after).\n")
    if fixture_commit := report.get("fixture_commit"):
        print(f"Loaded fixtures from Git commit `{fixture_commit}`.\n")
    if "capture_summary" in fixtures[0]:
        print(f"Verified SHA-256 against capture summaries for {len(fixtures)} fixture(s).\n")
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


def compare(fixtures, baseline_rule_sets, after, executable, revisions, gate, json_report, fixture_commit, *, bundles=()):
    promtool = shutil.which(executable)
    if not promtool:
        raise ValueError(f"promtool executable not found: {executable}")

    with TemporaryDirectory() as temporary:
        path = Path(temporary)
        before_failures = test_rule_version(promtool, fixtures, baseline_rule_sets, path / "before")
        after_failures = test_rule_version(promtool, fixtures, [after] * len(fixtures), path / "after")

    report = build_comparison_report(fixtures, before_failures, after_failures, revisions, gate, fixture_commit)
    if len(bundles) == 1:
        report["bundle"] = bundles[0]
    elif bundles:
        report["bundles"] = list(bundles)
    if json_report is not None:
        try:
            write_new_json(json_report, report)
        except FileExistsError as exc:
            raise ValueError(f"JSON report already exists: {json_report}") from exc
    print_markdown_report(report)
    return int(not report["gate"]["passed"])


def add_comparison_report_options(parser):
    parser.add_argument("--promtool", default="promtool", help="promtool executable or path")
    parser.add_argument("--json-report", type=Path, help="also write a machine-readable report to this new path")
    parser.add_argument(
        "--gate", choices=("strict", "regressions"), default="strict",
        help="fail on any proposed mismatch or only on newly failing checkpoints (default: strict)",
    )


def comparison_rule_bytes(sources, rule_format):
    if rule_format == "kubernetes":
        from kubernetes_rules import convert_manifests

        return convert_manifests(sources)
    return [content for _, content in sources]


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
    parser.add_argument("--fixture-ref", help="read fixtures and capture summaries from this Git ref (Git comparison only)")
    parser.add_argument(
        "--capture-summary", type=Path, action="append",
        help="verify the fixture hash against this capture summary (one per fixture, in the same order)",
    )
    parser.add_argument(
        "--rule-format", choices=("prometheus", "kubernetes"), default="prometheus",
        help="input rule format for both versions (default: prometheus)",
    )
    add_comparison_report_options(parser)
    args = parser.parse_args(argv)
    git_mode = any(value is not None for value in (args.before_ref, args.after_ref, args.rule_file, args.repo))
    if args.fixture_ref is not None and not git_mode:
        parser.error("--fixture-ref requires Git rule comparison")
    if args.capture_summary is not None and len(args.capture_summary) != len(args.fixtures):
        parser.error("provide one --capture-summary per incident fixture, in the same order")
    if git_mode and (args.before or args.after):
        parser.error("choose either --before and --after or Git ref comparison options")
    if git_mode and not (args.before_ref and args.after_ref and args.rule_file):
        parser.error("Git comparison requires --before-ref, --after-ref and at least one --rule-file")
    if not git_mode and not (args.before and args.after):
        parser.error("file comparison requires both --before and --after")
    try:
        repo = None
        revisions = None
        fixture_commit = None
        if git_mode:
            repo = args.repo or Path.cwd()
            revisions = (resolve_commit(repo, args.before_ref), resolve_commit(repo, args.after_ref))
            if args.fixture_ref is not None:
                fixture_commit = resolve_commit(repo, args.fixture_ref)
            before = read_committed_rules(repo, revisions[0], args.rule_file)
            after = read_committed_rules(repo, revisions[1], args.rule_file)
        else:
            before = read_rule_sources(args.before)
            after = read_rule_sources(args.after)
        fixtures = load_replay_fixtures(args.fixtures, args.capture_summary, repo, fixture_commit)
        before_rules = comparison_rule_bytes(before, args.rule_format)
        after_rules = comparison_rule_bytes(after, args.rule_format)
        return compare(
            fixtures, [before_rules] * len(fixtures), after_rules, args.promtool, revisions=revisions,
            gate=args.gate, json_report=args.json_report, fixture_commit=fixture_commit,
        )
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"error: {exc}\n")


def compare_bundle_main(argv):
    parser = argparse.ArgumentParser(
        prog=f"{Path(sys.argv[0]).name} compare-bundle",
        description="Compare proposed rules with the archived baseline and fixture in each incident bundle.",
    )
    parser.add_argument("bundles", metavar="bundle", nargs="+", help="ZIP archives created with bundle (repository-root-relative in Git mode)")
    parser.add_argument("--after", type=Path, action="append", help="proposed rule file in the working tree (repeatable)")
    parser.add_argument("--bundle-ref", help="Git ref or commit containing the bundles")
    parser.add_argument("--after-ref", help="Git ref or commit containing the proposed rules")
    parser.add_argument("--rule-file", action="append", help="repository-root-relative rule path at --after-ref (repeatable)")
    parser.add_argument("--repo", type=Path, help="Git repository for ref comparison (default: current directory)")
    parser.add_argument(
        "--rule-format", choices=("prometheus", "kubernetes"), default="prometheus",
        help="input format of the proposed rule files (default: prometheus)",
    )
    add_comparison_report_options(parser)
    args = parser.parse_args(argv)
    git_mode = any(value is not None for value in (args.bundle_ref, args.after_ref, args.rule_file, args.repo))
    if git_mode and args.after:
        parser.error("choose either --after files or Git ref comparison options")
    if git_mode and not (args.bundle_ref and args.after_ref and args.rule_file):
        parser.error("Git bundle comparison requires --bundle-ref, --after-ref and at least one --rule-file")
    if not git_mode and not args.after:
        parser.error("file bundle comparison requires at least one --after rule file")
    try:
        identities = args.bundles if git_mode else [os.path.realpath(path, strict=True) for path in args.bundles]
        if len(identities) != len(set(identities)):
            raise ValueError("each incident bundle must be supplied only once")
        revisions = None
        if git_mode:
            repo = args.repo or Path.cwd()
            revisions = (resolve_commit(repo, args.bundle_ref), resolve_commit(repo, args.after_ref))
            replays = [load_committed_bundle_replay(repo, revisions[0], path) for path in args.bundles]
            after = read_committed_rules(repo, revisions[1], args.rule_file)
        else:
            replays = [load_bundle_replay(Path(path)) for path in args.bundles]
            after = read_rule_sources(args.after)
        fixtures, baseline_rule_sets, bundles = zip(*replays)
        return compare(
            fixtures, baseline_rule_sets, comparison_rule_bytes(after, args.rule_format), args.promtool, revisions=revisions,
            gate=args.gate, json_report=args.json_report, fixture_commit=None, bundles=bundles,
        )
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


def add_capture_source_options(parser):
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--prometheus-url", help="query a Prometheus server for raw historical samples")
    source.add_argument("--matrix", type=Path, action="append", help="read a saved raw query response (repeatable)")


def add_fixture_generation_options(parser):
    parser.add_argument("--rule-file", type=Path, action="append", help="override config rule_files (repeatable)")
    parser.add_argument("--round-up", action="store_true", help="shift off-grid samples with a numeric sample interval")
    parser.add_argument("--max-shift", metavar="DURATION", help="allow bounded forward shifts if the exact auto grid is too large")


def bundle_main(argv):
    parser = argparse.ArgumentParser(
        prog=f"{Path(sys.argv[0]).name} bundle",
        description="Package raw samples, a replay fixture, native rules, and reports for offline use.",
    )
    parser.add_argument("config", type=Path, help="incident window and expected alert states (JSON)")
    add_capture_source_options(parser)
    add_fixture_generation_options(parser)
    parser.add_argument("--output", required=True, type=Path, help="new ZIP archive")
    args = parser.parse_args(argv)
    try:
        summary = write_bundle(args)
    except FileExistsError:
        parser.exit(1, f"error: output file already exists: {args.output}\n")
    except (ValueError, KeyError, TypeError, AttributeError, InvalidOperation, OSError, OverflowError) as exc:
        parser.exit(1, f"error: {exc}\n")
    print(f"Wrote {args.output} ({summary['series_count']} series, {summary['checkpoint_count']} checkpoints).")


def verify_bundle_main(argv):
    parser = argparse.ArgumentParser(
        prog=f"{Path(sys.argv[0]).name} verify-bundle",
        description="Verify the member inventory and recorded SHA-256 hashes of an incident bundle ZIP.",
    )
    parser.add_argument("bundle", type=Path, help="incident ZIP containing a manifest")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="report format (default: markdown)")
    args = parser.parse_args(argv)
    try:
        report = verify_bundle(args.bundle)
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        parser.exit(2, f"error: {exc}\n")
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        files = report["verified_files"]
        print(f"Verified SHA-256 for {len(files)} files in bundle {markdown_code(report['bundle_path'])}.\n")
        for name in files:
            print(f"- {markdown_code(name)}")


def plan_capture_main(argv):
    parser = argparse.ArgumentParser(
        prog=f"{Path(sys.argv[0]).name} plan-capture",
        description="Find candidate raw metric selectors for alerts and their recording-rule dependencies.",
    )
    parser.add_argument("rules", metavar="rule-file", nargs="+", type=Path, help="native Prometheus rule files")
    parser.add_argument("--alertname", required=True, action="append", help="alert rule name (repeatable)")
    parser.add_argument("--prometheus-url", required=True, help="Prometheus server providing /api/v1/parse_query")
    args = parser.parse_args(argv)
    if any(not name.strip() for name in args.alertname):
        parser.error("--alertname must not be empty")
    from capture_planner import plan_capture

    try:
        base_url = prometheus_base_url(args.prometheus_url)
        sources = read_rule_sources(args.rules)
        report = plan_capture(sources, args.alertname, lambda expression: fetch_promql_ast(base_url, expression))
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))


def snapshot_main(argv):
    parser = argparse.ArgumentParser(
        prog=f"{Path(sys.argv[0]).name} snapshot",
        description="Save raw Prometheus samples in a matrix JSON file for offline fixture generation.",
    )
    parser.add_argument("config", type=Path, help="capture window and selectors (JSON)")
    add_capture_source_options(parser)
    parser.add_argument("--output", required=True, type=Path, help="new matrix JSON file")
    args = parser.parse_args(argv)
    try:
        config = read_json(args.config)
        (_, begin_ms), (end, end_ms) = capture_window(config)
        matrices = capture_matrices(args, config, end, end_ms - begin_ms)
        samples = capture_samples(matrices, begin_ms, end_ms)
        write_matrix_snapshot(args.output, samples, begin_ms)
    except FileExistsError:
        parser.exit(1, f"error: output file already exists: {args.output}\n")
    except (ValueError, KeyError, TypeError, AttributeError, InvalidOperation, OSError) as exc:
        parser.exit(1, f"error: {exc}\n")
    sample_count = sum(len(series.samples) for series in samples.values())
    print(f"Wrote {args.output} ({len(samples)} series, {sample_count} samples).")


def inspect_main(argv):
    parser = argparse.ArgumentParser(
        prog=f"{Path(sys.argv[0]).name} inspect",
        description="Report observed sample coverage and time gaps in a Prometheus capture window.",
    )
    parser.add_argument("config", type=Path, help="capture window and selectors (JSON)")
    add_capture_source_options(parser)
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="report format (default: markdown)")
    parser.add_argument("--max-gap", metavar="DURATION", help="fail on empty captures or gaps exceeding this positive duration")
    args = parser.parse_args(argv)
    try:
        max_gap_ms = None
        if args.max_gap is not None:
            max_gap_ms = duration_ms(args.max_gap)
            if max_gap_ms <= 0:
                raise ValueError("--max-gap requires a positive duration")
        config = read_json(args.config)
        (start, begin_ms), (end, end_ms) = capture_window(config)
        matrices = capture_matrices(args, config, end, end_ms - begin_ms)
        samples = capture_samples(matrices, begin_ms, end_ms, allow_empty=True)
        report = build_coverage_report(samples, start, end, max_gap_ms)
    except (ValueError, KeyError, TypeError, AttributeError, InvalidOperation, OSError, OverflowError) as exc:
        parser.exit(2, f"error: {exc}\n")
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_coverage_report(report)
    return int(report["gate"] is not None and not report["gate"]["passed"])


def main():
    if sys.argv[1:2] == ["bundle"]:
        return bundle_main(sys.argv[2:])
    if sys.argv[1:2] == ["verify-bundle"]:
        return verify_bundle_main(sys.argv[2:])
    if sys.argv[1:2] == ["plan-capture"]:
        return plan_capture_main(sys.argv[2:])
    if sys.argv[1:2] == ["snapshot"]:
        return snapshot_main(sys.argv[2:])
    if sys.argv[1:2] == ["inspect"]:
        return inspect_main(sys.argv[2:])
    if sys.argv[1:2] == ["compare"]:
        return compare_main(sys.argv[2:])
    if sys.argv[1:2] == ["compare-bundle"]:
        return compare_bundle_main(sys.argv[2:])
    if sys.argv[1:2] == ["export-rules"]:
        return export_rules_main(sys.argv[2:])
    parser = argparse.ArgumentParser(
        description=__doc__, epilog="See bundle --help for portable captures, verify-bundle --help for archive checks, "
        "plan-capture --help for metric selectors, "
        "snapshot --help for sample capture, "
        "inspect --help for sample coverage, compare --help and compare-bundle --help for rule comparisons, "
        "or export-rules --help for Kubernetes manifests."
    )
    parser.add_argument("config", type=Path, help="incident window and expected alert states (JSON)")
    add_capture_source_options(parser)
    add_fixture_generation_options(parser)
    parser.add_argument("--summary-format", choices=("text", "json"), default="text",
                        help="write a plain-text or JSON capture summary to stdout (default: text)")
    parser.add_argument("--output", required=True, type=Path, help="new promtool YAML test file")
    args = parser.parse_args()
    try:
        summary = generate(args)
    except FileExistsError:
        parser.exit(1, f"error: output file already exists: {args.output}\n")
    except (ValueError, KeyError, TypeError, AttributeError, InvalidOperation, OSError) as exc:
        parser.exit(1, f"error: {exc}\n")
    if args.summary_format == "json":
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return
    print(f"Wrote {summary['fixture_path']} ({summary['series_count']} series, {summary['checkpoint_count']} checkpoints).")
    if summary["sampling_mode"].startswith("auto_"):
        print(f"Automatically selected a {as_duration(summary['sample_interval_ms'])} sample interval.")
    shift = summary["max_shift_ms"]
    if shift:
        print(f"Shifted off-grid samples forward by up to {shift} ms.", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
