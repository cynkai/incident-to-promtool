#!/usr/bin/env python3
"""Create and compare offline promtool rule tests from historical samples."""

import argparse
from contextlib import ExitStack, contextmanager, suppress
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
MAX_TIMELINE_TICKS = 10_000
BUNDLE_FIXTURE = "incident.test.yml"
BUNDLE_CAPTURE_SUMMARY = "capture.json"
BUNDLE_RULE_PATH = re.compile(r"rules/rules-[1-9][0-9]*\.yml")
BUNDLE_MANIFEST = "manifest.json"
BUNDLE_MANIFEST_VERSION = 1
BUNDLE_FIXED_FILES = (
    "incident.json", "incident.matrix.json", BUNDLE_FIXTURE, BUNDLE_CAPTURE_SUMMARY, "coverage.json",
)
SHA256_HEX = re.compile(r"[0-9a-fA-F]{64}")
XML_INVALID = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


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
def staged_output_file(path, mode, **options):
    temporary = NamedTemporaryFile(mode, dir=path.parent, delete=False, **options)
    try:
        yield temporary
    finally:
        temporary.close()
        Path(temporary.name).unlink()


@contextmanager
def new_output_file(path, mode, **options):
    with staged_output_file(path, mode, **options) as temporary:
        with temporary:
            yield temporary
        os.link(temporary.name, path)


def json_document(data):
    return (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def write_new_json(path, data):
    document = json_document(data)
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
        raise ValueError(f"{path}: expected a JSON-formatted fixture generated by this CLI") from exc
    groups = data.get("tests") if isinstance(data, dict) else None
    if not isinstance(groups, list) or not groups or any(
        not isinstance(group, dict)
        or not isinstance(group.get("alert_rule_test"), list)
        or not group["alert_rule_test"]
        or group.get("promql_expr_test")
        for group in groups
    ):
        raise ValueError(f"{path}: expected a generated fixture with alert checkpoints in every test group")
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


def unique_json_object(pairs):
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
        document = json.loads(contents.decode("utf-8"), object_pairs_hook=unique_json_object)
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


def load_bundle_replay(path, *, source=None, include_archived_rules=True):
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
        rules = []
        if include_archived_rules:
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


def load_committed_bundle_replay(repo, revision, path, *, include_archived_rules=True):
    object_id = committed_file_id(repo, revision, path, "bundle")
    with TemporaryFile() as source:
        git_output(repo, "cat-file", "blob", object_id, stdout=source)
        source.seek(0)
        return load_bundle_replay(path, source=source, include_archived_rules=include_archived_rules)


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


def require_promtool(executable):
    promtool = shutil.which(executable)
    if not promtool:
        raise ValueError(f"promtool executable not found: {executable}")
    return promtool


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
    rule_paths = report.get("rule_files")
    if bundle or bundles:
        anchor = f" at Git commit `{commits['before']}`" if commits else ""
        if bundle:
            files = "the fixture" if rule_paths else "the baseline rules and fixture"
            print(f"Loaded {files} from bundle {markdown_code(bundle['path'])}{anchor}.\n")
        else:
            files = "fixtures" if rule_paths else "baseline rules and fixtures"
            print(f"Loaded {files} from {len(bundles)} bundles{anchor}.\n")
        if commits:
            if rule_paths:
                print(f"Read baseline rules from Git commit `{commits['before']}`.\n")
            print(f"Read proposed rules from Git commit `{commits['after']}`.\n")
    elif commits:
        print(f"Compared Git commits `{commits['before']}` and `{commits['after']}` (before and after).\n")
    if rule_paths:
        for version in versions:
            paths = ", ".join(markdown_code(path) for path in rule_paths[version])
            print(f"{version.title()} rule files {paths}.\n")
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


def build_junit_report(fixtures, report):
    zero_counts = {"errors": "0", "skipped": "0"}
    timelines = report.get("timeline_policy", {}).get("checks", ())
    if "timeline" in report:
        timelines = (report["timeline"],)
    test_count = report["summary"]["after"]["total"] + len(timelines)
    root = ElementTree.Element("testsuites", {
        "name": "incident-to-promtool", "tests": str(test_count), **zero_counts,
    })
    strict = report["gate"]["mode"] == "strict"
    failures = 0
    for fixture, result in zip(fixtures, report["fixtures"], strict=True):
        name = XML_INVALID.sub("\ufffd", result["path"])
        suite = ElementTree.SubElement(root, "testsuite", {
            "name": name, "tests": str(fixture.checkpoints), **zero_counts,
        })
        changes = {(change["group"], change["alertname"], change["offset_ms"]): change for change in result["changes"]}
        suite_failures = 0
        for group, checkpoints in enumerate(fixture.checkpoint_keys, start=1):
            for alert, offset in sorted(checkpoints):
                title = XML_INVALID.sub("\ufffd", f"{alert} @ {as_duration(offset)} [group {group}]")
                case = ElementTree.SubElement(suite, "testcase", {"classname": name, "name": title})
                change = changes.get((group, alert, offset))
                if change is None:
                    continue
                kind = change["change"]
                details = "\n\n".join(
                    f"{label}\n{change[key].strip()}" for label, key in (
                        ("Baseline", "before_diagnostic"), ("Proposed", "after_diagnostic"),
                    ) if change[key] is not None
                )
                if kind == "newly_failed" or (strict and kind == "still_failing"):
                    message = "Newly failed checkpoint" if kind == "newly_failed" else "Still failing checkpoint"
                    failure = ElementTree.SubElement(case, "failure", {"message": message, "type": kind})
                    failure.text = XML_INVALID.sub("\ufffd", details)
                    suite_failures += 1
                else:
                    message = "Fixed checkpoint." if kind == "fixed" else "Still failing. Allowed by the regressions gate."
                    ElementTree.SubElement(case, "system-out").text = XML_INVALID.sub("\ufffd", f"{message}\n\n{details}")
        suite.set("failures", str(suite_failures))
        failures += suite_failures
    if timelines:
        timing_failures = sum(not timeline_passed(timeline) for timeline in timelines)
        suite = ElementTree.SubElement(root, "testsuite", {
            "name": "Alert firing delay", "tests": str(len(timelines)), "failures": str(timing_failures), **zero_counts,
        })
        for timeline in timelines:
            add_timeline_junit_case(suite, timeline)
        failures += timing_failures
    root.set("failures", str(failures))
    ElementTree.indent(root)
    return ElementTree.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"


def add_timeline_junit_case(suite, timeline):
    limits = []
    if delay := timeline.get("gate"):
        limits.append(f"max delay {as_duration(delay['max_delay_ms'])}")
    if deadline := timeline.get("deadline_gate"):
        limits.append(f"fire by {as_duration(deadline['fire_by_ms'])}")
    title = f"{timeline['alertname']} ({', '.join(limits)})"
    case = ElementTree.SubElement(suite, "testcase", {
        "classname": XML_INVALID.sub("\ufffd", timeline["fixture_path"]),
        "name": XML_INVALID.sub("\ufffd", title),
    })
    if timeline_passed(timeline):
        return
    if delay and deadline:
        message, kind = "Alert timing gate failed", "timing"
        details = {"gate": delay, "deadline_gate": deadline, "passed": False}
    elif deadline:
        message, kind, details = "Alert firing deadline gate failed", "fire-by", deadline
    else:
        message, kind, details = "Alert firing delay gate failed", "max-delay", delay
    failure = ElementTree.SubElement(case, "failure", {"message": message, "type": kind})
    failure.text = json.dumps(details, indent=2)


def write_comparison_reports(reports):
    with ExitStack() as resources:
        staged = []
        for kind, destination, document in reports:
            with resources.enter_context(staged_output_file(destination, "wb")) as output:
                output.write(document)
            staged.append((kind, destination, Path(output.name)))

        published = []
        try:
            for kind, destination, source in staged:
                try:
                    os.link(source, destination)
                except FileExistsError as exc:
                    raise ValueError(f"{kind} report already exists: {destination}") from exc
                published.append((source, destination))
        except BaseException:
            for source, destination in reversed(published):
                with suppress(OSError):
                    if os.path.samestat(source.stat(), destination.lstat()):
                        destination.unlink()
            raise


def compare(
    fixtures, baseline_rule_sets, after, executable, revisions, gate, json_report, fixture_commit,
    *, bundles=(), junit_report=None, rule_paths=None, show_rule_paths=True, timelines=(), timeline_policy=None,
):
    if (json_report is not None and junit_report is not None
            and os.path.realpath(json_report) == os.path.realpath(junit_report)):
        raise ValueError("JSON and JUnit reports require distinct output paths")
    promtool = require_promtool(executable)

    replay_fixtures = fixtures
    if timelines:
        # Stage timing probes beside the checkpoint fixtures using the same rule bytes.
        replay_fixtures = [*fixtures, *(timeline.probes for _, timeline in timelines)]
        baseline_rule_sets = [*baseline_rule_sets, *(baseline_rule_sets[index] for index, _ in timelines)]
    with TemporaryDirectory() as temporary:
        path = Path(temporary)
        before_failures = test_rule_version(promtool, replay_fixtures, baseline_rule_sets, path / "before")
        after_failures = test_rule_version(promtool, replay_fixtures, [after] * len(replay_fixtures), path / "after")

    fixture_count = len(fixtures)
    timing_reports = []
    for (index, timeline), before_probes, after_probes in zip(
        timelines, before_failures[fixture_count:], after_failures[fixture_count:], strict=True,
    ):
        timing_report = build_timeline_report(timeline, before_probes, after_probes)
        add_timeline_provenance(
            timing_report, timeline.fixture, revisions, rule_paths, fixture_commit,
            bundle=bundles[index] if bundles else None,
        )
        timing_reports.append(timing_report)
    timing_passed = all(timeline_passed(timing_report) for timing_report in timing_reports)
    report = build_comparison_report(
        fixtures, before_failures[:fixture_count], after_failures[:fixture_count], revisions, gate, fixture_commit,
    )
    if len(bundles) == 1:
        report["bundle"] = bundles[0]
    elif bundles:
        report["bundles"] = list(bundles)
    if show_rule_paths and rule_paths is not None:
        report["rule_files"] = rule_paths
    if timeline_policy is not None:
        report["timeline_policy"] = {**timeline_policy, "passed": timing_passed, "checks": timing_reports}
    elif timing_reports:
        report["timeline"] = timing_reports[0]
    reports = []
    if json_report is not None:
        reports.append(("JSON", json_report, json_document(report)))
    if junit_report is not None:
        reports.append(("JUnit", junit_report, build_junit_report(fixtures, report)))
    if reports:
        write_comparison_reports(reports)
    print_markdown_report(report)
    if timeline_policy is not None:
        print_timeline_policy(report["timeline_policy"])
    elif timing_reports:
        print()
        print_timeline_report(timing_reports[0])
    return int(not (report["gate"]["passed"] and timing_passed))


def add_comparison_report_options(parser):
    parser.add_argument("--promtool", default="promtool", help="promtool executable or path")
    parser.add_argument("--json-report", type=Path, help="also write a machine-readable report to this new path")
    parser.add_argument("--junit-report", type=Path, help="also write a JUnit XML report to this new path")
    parser.add_argument(
        "--gate", choices=("strict", "regressions"), default="strict",
        help="fail on any proposed mismatch or only on newly failing checkpoints (default: strict)",
    )


def add_rule_comparison_options(parser):
    parser.add_argument("--before", type=Path, action="append", help="baseline rule file (repeatable)")
    parser.add_argument("--after", type=Path, action="append", help="proposed rule file (repeatable)")
    parser.add_argument("--before-ref", help="baseline Git ref or commit")
    parser.add_argument("--after-ref", help="proposed Git ref or commit")
    parser.add_argument("--rule-file", action="append", help="repository-root-relative path present in both commits (repeatable)")
    parser.add_argument("--before-rule-file", action="append", help="repository-root-relative rule path at --before-ref (repeatable)")
    parser.add_argument("--after-rule-file", action="append", help="repository-root-relative rule path at --after-ref (repeatable)")
    parser.add_argument("--repo", type=Path, help="Git repository for ref comparison (default: current directory)")
    parser.add_argument("--fixture-ref", help="read test fixtures and capture summaries from this Git ref (Git comparison only)")
    parser.add_argument(
        "--rule-format", choices=("prometheus", "kubernetes"), default="prometheus",
        help="input rule format for both versions (default: prometheus)",
    )


@dataclass(frozen=True)
class ComparisonRuleSources:
    before: list[tuple[str, bytes]]
    after: list[tuple[str, bytes]]
    repo: Path | None = None
    revisions: tuple[str, str] | None = None
    fixture_commit: str | None = None
    rule_paths: dict[str, list[str]] | None = None


def load_comparison_rules(parser, args):
    scoped_paths = args.before_rule_file is not None or args.after_rule_file is not None
    git_mode = scoped_paths or any(value is not None for value in (args.before_ref, args.after_ref, args.rule_file, args.repo))
    if args.fixture_ref is not None and not git_mode:
        parser.error("--fixture-ref requires Git rule comparison")
    if not git_mode:
        if not (args.before and args.after):
            parser.error("file comparison requires both --before and --after")
        return ComparisonRuleSources(read_rule_sources(args.before), read_rule_sources(args.after))

    if args.before or args.after:
        parser.error("choose either --before and --after or Git ref comparison options")
    if not (args.before_ref and args.after_ref):
        parser.error("Git comparison requires --before-ref and --after-ref")
    if scoped_paths and args.rule_file:
        parser.error("choose either --rule-file or the --before-rule-file and --after-rule-file lists")
    if scoped_paths and not (args.before_rule_file and args.after_rule_file):
        parser.error("provide both --before-rule-file and --after-rule-file lists")
    if not (scoped_paths or args.rule_file):
        parser.error("provide --rule-file or both --before-rule-file and --after-rule-file lists")

    repo = args.repo or Path.cwd()
    revisions = (resolve_commit(repo, args.before_ref), resolve_commit(repo, args.after_ref))
    fixture_commit = resolve_commit(repo, args.fixture_ref) if args.fixture_ref is not None else None
    before_paths = args.before_rule_file if scoped_paths else args.rule_file
    after_paths = args.after_rule_file if scoped_paths else args.rule_file
    return ComparisonRuleSources(
        read_committed_rules(repo, revisions[0], before_paths), read_committed_rules(repo, revisions[1], after_paths),
        repo=repo, revisions=revisions, fixture_commit=fixture_commit,
        rule_paths={"before": before_paths, "after": after_paths},
    )


def comparison_rule_bytes(sources, rule_format):
    if rule_format == "kubernetes":
        from kubernetes_rules import convert_manifests

        return convert_manifests(sources)
    return [content for _, content in sources]


def timeline_probes(fixture, alertname, start, end, *, probe_from_zero=False, tick_budget=None):
    try:
        evaluation = duration_ms(fixture.data.get("evaluation_interval"))
    except ValueError as exc:
        raise ValueError(f"{fixture.path}: invalid or missing evaluation_interval") from exc
    if not 0 < evaluation <= MAX_PROMTOOL_DURATION_MS:
        raise ValueError(f"{fixture.path}: evaluation_interval must be a positive supported duration")
    if start > end or end > MAX_PROMTOOL_DURATION_MS:
        raise ValueError("the timeline range requires start <= end and an end within promtool's supported duration")
    if start % evaluation or end % evaluation:
        raise ValueError("--start and --end must align with the fixture's evaluation ticks")

    selected_groups = [
        number for number, keys in enumerate(fixture.checkpoint_keys, start=1)
        if any(name == alertname for name, _ in keys)
    ]
    if not selected_groups:
        raise ValueError(f"{fixture.path}: no checkpoints for alert {alertname!r}")
    evaluation_ticks = len(selected_groups) * (end // evaluation + 1)
    if evaluation_ticks > (MAX_TIMELINE_TICKS if tick_budget is None else tick_budget):
        limit = f"more than {MAX_TIMELINE_TICKS:,} evaluation ticks per rule version"
        if tick_budget is not None:
            raise ValueError(f"timeline policy would simulate {limit}; shorten one or more check end values")
        raise ValueError(f"timeline would simulate {limit}; shorten --end")

    # An empty expected alert set differs from Promtool's result exactly at firing ticks.
    ticks = range(0 if probe_from_zero else start, end + 1, evaluation)
    checks = [{"alertname": alertname, "eval_time": as_duration(offset), "exp_alerts": []} for offset in ticks]
    groups = [
        {**fixture.data["tests"][number - 1], "alert_rule_test": checks}
        for number in selected_groups
    ]
    keys = {(alertname, offset) for offset in ticks}
    probes = ReplayFixture(fixture.path, {**fixture.data, "tests": groups}, [keys] * len(groups), None, None)
    return probes, selected_groups, evaluation, evaluation_ticks


def firing_offsets(mismatches, group_count):
    offsets = [[] for _ in range(group_count)]
    for group, _, offset in mismatches:
        offsets[group - 1].append(offset)

    for firing in offsets:
        firing.sort()
    return offsets


def firing_timeline(firing, evaluation):
    intervals = []
    for offset in firing:
        if intervals and offset == intervals[-1]["end_offset_ms"] + evaluation:
            intervals[-1]["end_offset_ms"] = offset
        else:
            intervals.append({"start_offset_ms": offset, "end_offset_ms": offset})
    return {
        "first_firing_offset_ms": firing[0] if firing else None,
        "firing_ticks": len(firing),
        "firing_intervals": intervals,
    }


def firing_delta(before, after):
    return after - before if before is not None and after is not None else None


def timeline_delay_result(group, baseline, candidate, max_delay):
    first_before = baseline[0] if baseline else None
    first_after = candidate[0] if candidate else None
    delta = firing_delta(first_before, first_after)
    if first_before is None:
        status = "no_baseline"
    elif first_after is None:
        status = "missing_after"
    elif delta > max_delay:
        status = "delayed"
    else:
        status = "passed"
    return {
        "group": group,
        "status": status,
        "before_first_firing_offset_ms": first_before,
        "after_first_firing_offset_ms": first_after,
        "first_firing_delta_ms": delta,
    }


def timeline_deadline_result(group, candidate, fire_by):
    first_after = candidate[0] if candidate else None
    if first_after is None:
        status = "missing_after"
    elif first_after > fire_by:
        status = "late"
    else:
        status = "passed"
    return {"group": group, "status": status, "after_first_firing_offset_ms": first_after}


@dataclass(frozen=True)
class TimelineReplay:
    fixture: ReplayFixture
    probes: ReplayFixture
    group_numbers: list[int]
    evaluation: int
    evaluation_ticks: int
    alertname: str
    start: int
    end: int
    max_delay: int | None
    fire_by: int | None
    deadline_groups: set[int]


def prepare_timeline(fixture, alertname, start, end, max_delay, *, fire_by=None, tick_budget=None):
    deadline_groups = set()
    if fire_by is not None:
        if fire_by > end:
            raise ValueError("the fire-by deadline must be at or before the timeline end")
        deadline_groups = {
            number for number, group in enumerate(fixture.data["tests"], start=1)
            if any(
                checkpoint["alertname"] == alertname
                and isinstance(checkpoint.get("exp_alerts"), list) and checkpoint["exp_alerts"]
                for checkpoint in group["alert_rule_test"]
            )
        }
        if not deadline_groups:
            raise ValueError(f"{fixture.path}: fire-by requires at least one positive checkpoint for alert {alertname!r}")
    probes, group_numbers, evaluation, evaluation_ticks = timeline_probes(
        fixture, alertname, start, end, probe_from_zero=max_delay is not None or fire_by is not None,
        tick_budget=tick_budget,
    )
    return TimelineReplay(
        fixture, probes, group_numbers, evaluation, evaluation_ticks, alertname, start, end, max_delay,
        fire_by, deadline_groups,
    )


def build_timeline_report(timeline, before, after):
    group_numbers = timeline.group_numbers
    start, evaluation, max_delay = timeline.start, timeline.evaluation, timeline.max_delay
    groups = []
    gate_groups = []
    deadline_results = []
    for number, before_offsets, after_offsets in zip(
        group_numbers, firing_offsets(before, len(group_numbers)), firing_offsets(after, len(group_numbers)), strict=True,
    ):
        baseline = firing_timeline([offset for offset in before_offsets if offset >= start], evaluation)
        candidate = firing_timeline([offset for offset in after_offsets if offset >= start], evaluation)
        groups.append({
            "group": number, "before": baseline, "after": candidate,
            "first_firing_delta_ms": firing_delta(baseline["first_firing_offset_ms"], candidate["first_firing_offset_ms"]),
        })
        if max_delay is not None:
            gate_groups.append(timeline_delay_result(number, before_offsets, after_offsets, max_delay))
        if number in timeline.deadline_groups:
            deadline_results.append(timeline_deadline_result(number, after_offsets, timeline.fire_by))
    report = {
        "schema_version": 1,
        "fixture_path": str(timeline.fixture.path),
        "alertname": timeline.alertname,
        "evaluation_interval_ms": evaluation,
        "start_offset_ms": start,
        "end_offset_ms": timeline.end,
        "groups": groups,
    }
    if max_delay is not None:
        checked = sum(group["status"] != "no_baseline" for group in gate_groups)
        report["gate"] = {
            "mode": "max-delay",
            "max_delay_ms": max_delay,
            "passed": checked > 0 and all(group["status"] in ("passed", "no_baseline") for group in gate_groups),
            "checked_groups": checked,
            "groups": gate_groups,
        }
    if timeline.fire_by is not None:
        report["deadline_gate"] = {
            "mode": "fire-by",
            "fire_by_ms": timeline.fire_by,
            "passed": all(group["status"] == "passed" for group in deadline_results),
            "checked_groups": len(deadline_results),
            "groups": deadline_results,
        }
        report["passed"] = timeline_passed(report)
    return report


def timeline_passed(report):
    return all(report[key]["passed"] for key in ("gate", "deadline_gate") if key in report)


def add_timeline_provenance(report, fixture, revisions, rule_paths, fixture_commit, *, bundle=None):
    if bundle is not None:
        report["bundle"] = bundle
        if "before" in rule_paths:
            report["baseline_source"] = "rules"
        else:
            report["baseline_source"] = "bundle"
            rule_paths = {"before": bundle["rule_files"], "after": rule_paths["after"]}
        if revisions is not None:
            fixture_commit = revisions[0]
    if revisions is not None:
        before_commit, after_commit = revisions
        report["commits"] = {"before": before_commit, "after": after_commit}
    if rule_paths is not None:
        report["rule_files"] = rule_paths
    if fixture_commit is not None:
        report["fixture_commit"] = fixture_commit
    if fixture.sha256 is not None:
        report["fixture_sha256"] = fixture.sha256
    if fixture.capture_summary is not None:
        report["capture_summary"] = str(fixture.capture_summary)


def format_observed_offset(offset):
    return as_duration(offset) if offset is not None else "—"


def format_timeline_shift(delta):
    if delta is None:
        return "—"
    if delta == 0:
        return "0s"
    return f"{as_duration(abs(delta))} {'earlier' if delta < 0 else 'later'}"


def print_timeline_gate(gate, end):
    limit = as_duration(gate["max_delay_ms"])
    verdict = "Passed" if gate["passed"] else "Failed"
    print(f"\nTiming gate `max-delay {limit}` **{verdict}**. Measured from 0s through {end}.\n")
    if not gate["checked_groups"]:
        print("No baseline firing was observed in any selected group.\n")
    statuses = {
        "passed": "Within limit",
        "delayed": "Delay exceeds limit",
        "missing_after": "No candidate firing through end",
        "no_baseline": "No baseline firing observed",
    }
    print("| Group | Baseline first firing | Candidate first firing | Shift | Gate result |")
    print("| ---: | --- | --- | --- | --- |")
    for group in gate["groups"]:
        cells = [
            str(group["group"]), format_observed_offset(group["before_first_firing_offset_ms"]),
            format_observed_offset(group["after_first_firing_offset_ms"]),
            format_timeline_shift(group["first_firing_delta_ms"]), statuses[group["status"]],
        ]
        print("| " + " | ".join(cells) + " |")


def print_deadline_gate(gate, end):
    limit = as_duration(gate["fire_by_ms"])
    verdict = "Passed" if gate["passed"] else "Failed"
    print(f"\nTiming gate `fire-by {limit}` **{verdict}**. Measured from 0s through {end}.\n")
    statuses = {
        "passed": "Fired by deadline",
        "late": "Fired after deadline",
        "missing_after": "No candidate firing through end",
    }
    print("| Group | Candidate first firing | Gate result |")
    print("| ---: | --- | --- |")
    for group in gate["groups"]:
        offset = format_observed_offset(group["after_first_firing_offset_ms"])
        print(f"| {group['group']} | {offset} | {statuses[group['status']]} |")


def print_timeline_report(report, *, heading="##"):
    print(f"{heading} Prometheus alert firing timeline\n")
    print(f"{markdown_code(report['alertname'])} in {markdown_code(report['fixture_path'])}.\n")
    commits = report.get("commits")
    if rule_paths := report.get("rule_files"):
        for side in ("before", "after"):
            paths = ", ".join(markdown_code(path) for path in rule_paths[side])
            if side == "before" and report.get("baseline_source") == "bundle":
                location = f" in bundle {markdown_code(report['bundle']['path'])}"
            else:
                location = f" from Git commit `{commits[side]}`" if commits else ""
            print(f"{side.title()} rules{location} ({paths}).\n")
    if fixture_commit := report.get("fixture_commit"):
        print(f"Loaded the fixture from Git commit `{fixture_commit}`.\n")
    if checksum := report.get("fixture_sha256"):
        if summary := report.get("capture_summary"):
            print(f"Verified fixture SHA-256 `{checksum}` against {markdown_code(summary)}.\n")
        else:
            print(f"Fixture SHA-256 `{checksum}`.\n")
    start = as_duration(report["start_offset_ms"])
    end = as_duration(report["end_offset_ms"])
    step = as_duration(report["evaluation_interval_ms"])
    print(f"Observed every {step} from {start} through {end}, relative to each test group start.\n")
    print("| Group | Before first observed firing | After first observed firing | Shift | Before firing intervals | After firing intervals |")
    print("| ---: | --- | --- | --- | --- | --- |")
    for group in report["groups"]:
        first_firings, periods = [], []
        for side in ("before", "after"):
            timeline = group[side]
            first_firings.append(format_observed_offset(timeline["first_firing_offset_ms"]))
            intervals = []
            for interval in timeline["firing_intervals"]:
                first_tick, last_tick = interval["start_offset_ms"], interval["end_offset_ms"]
                first_label = as_duration(first_tick)
                intervals.append(first_label if first_tick == last_tick else f"{first_label}–{as_duration(last_tick)}")
            periods.append(", ".join(intervals) or "—")
        shift = format_timeline_shift(group["first_firing_delta_ms"])
        cells = [str(group["group"]), *first_firings, shift, *periods]
        print("| " + " | ".join(cells) + " |")
    if "gate" in report:
        print_timeline_gate(report["gate"], end)
    if "deadline_gate" in report:
        print_deadline_gate(report["deadline_gate"], end)


def print_timeline_policy(policy):
    checks = policy["checks"]
    passed = sum(timeline_passed(check) for check in checks)
    verdict = "Passed" if policy["passed"] else "Failed"
    print(f"\n## Alert firing delay policy\n\n**{verdict}** ({passed}/{len(checks)} checks) "
          f"for {markdown_code(policy['path'])}.\n")
    if commit := policy.get("commit"):
        print(f"Loaded the policy from Git commit `{commit}`.\n")
    print(f"Policy SHA-256 `{policy['sha256']}`.")
    for check in checks:
        print()
        print_timeline_report(check, heading="###")


def timeline_main(argv):
    parser = argparse.ArgumentParser(
        prog=f"{Path(sys.argv[0]).name} timeline",
        description="Compare firing offsets and intervals from the same incident fixture.",
    )
    parser.add_argument("fixture", type=Path, help="test fixture generated by this CLI")
    add_rule_comparison_options(parser)
    parser.add_argument(
        "--capture-summary", type=Path, action="append",
        help="verify the fixture hash against this capture summary",
    )
    parser.add_argument("--alertname", required=True, help="alert name from the fixture's checkpoints")
    parser.add_argument("--start", default="0s", metavar="DURATION", help="first offset to observe (default: 0s)")
    parser.add_argument("--end", required=True, metavar="DURATION", help="last offset to observe (inclusive)")
    parser.add_argument("--max-delay", metavar="DURATION", help="gate the first proposed firing against the baseline from 0s")
    parser.add_argument("--fire-by", metavar="DURATION", help="latest allowed first proposed firing from the test group start")
    parser.add_argument("--promtool", default="promtool", help="promtool executable or path")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="report format (default: markdown)")
    args = parser.parse_args(argv)
    if not args.alertname.strip():
        parser.error("--alertname must not be empty")
    if args.capture_summary is not None and len(args.capture_summary) != 1:
        parser.error("provide only one --capture-summary for the timeline fixture")
    try:
        sources = load_comparison_rules(parser, args)
        fixture, = load_replay_fixtures([args.fixture], args.capture_summary, sources.repo, sources.fixture_commit)
        start, end = duration_ms(args.start), duration_ms(args.end)
        max_delay = duration_ms(args.max_delay) if args.max_delay is not None else None
        fire_by = duration_ms(args.fire_by) if args.fire_by is not None else None
        timeline = prepare_timeline(fixture, args.alertname, start, end, max_delay, fire_by=fire_by)
        before_rules = comparison_rule_bytes(sources.before, args.rule_format)
        after_rules = comparison_rule_bytes(sources.after, args.rule_format)
        promtool = require_promtool(args.promtool)
        with TemporaryDirectory() as temporary:
            path = Path(temporary)
            before, = test_rule_version(promtool, [timeline.probes], [before_rules], path / "before")
            after, = test_rule_version(promtool, [timeline.probes], [after_rules], path / "after")
        report = build_timeline_report(timeline, before, after)
        add_timeline_provenance(report, fixture, sources.revisions, sources.rule_paths, sources.fixture_commit)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"error: {exc}\n")
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_timeline_report(report)
    return int(not timeline_passed(report))


def add_comparison_timeline_options(parser, source, *, path_type):
    parser.add_argument("--timeline-policy", type=Path, help="JSON file with one or more first-firing timing checks")
    parser.add_argument("--timeline-alertname", help="alert to check for first-firing timing")
    parser.add_argument("--timeline-end", metavar="DURATION", help="last offset to observe for the first-firing check")
    parser.add_argument("--timeline-max-delay", metavar="DURATION", help="maximum allowed first-firing delay")
    parser.add_argument("--timeline-fire-by", metavar="DURATION", help="latest allowed first proposed firing from the test group start")
    parser.add_argument(
        f"--timeline-{source}", type=path_type,
        help=f"one of the listed {source}s (required for timing with multiple {source}s)",
    )


def comparison_timeline_index(parser, args, paths, selection, source):
    limits = (args.timeline_max_delay, args.timeline_fire_by)
    options = (args.timeline_alertname, args.timeline_end, *limits)
    if args.timeline_policy is not None and (any(option is not None for option in options) or selection is not None):
        parser.error("--timeline-policy cannot be combined with individual timeline options")
    if all(option is None for option in options) and selection is None:
        return None
    if args.timeline_alertname is None or args.timeline_end is None or all(limit is None for limit in limits):
        parser.error("--timeline-alertname and --timeline-end are required together with --timeline-max-delay or --timeline-fire-by")
    if not args.timeline_alertname.strip():
        parser.error("--timeline-alertname must not be empty")
    if selection is None:
        if len(paths) != 1:
            parser.error(f"--timeline-{source} is required when comparing multiple {source}s")
        return 0
    if selection not in paths:
        parser.error(f"--timeline-{source} must match one of the supplied incident {source}s")
    return paths.index(selection)


def load_timeline_policy(path, repo, commit):
    contents = read_replay_bytes(path, repo, commit, "timeline policy")
    try:
        document = json.loads(contents.decode("utf-8"), object_pairs_hook=unique_json_object)
    except (ValueError, RecursionError) as exc:
        raise ValueError(f"{path}: invalid timeline policy JSON: {exc}") from exc
    version = document.get("schema_version") if isinstance(document, dict) else None
    if type(version) is not int or version != 1:
        raise ValueError(f"{path}: timeline policy requires schema_version 1")
    if document.keys() - {"schema_version", "checks"}:
        raise ValueError(f"{path}: timeline policy contains unknown fields")
    checks = document.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ValueError(f"{path}: timeline policy requires a nonempty checks array")
    origin = {"path": str(path), "sha256": hashlib.sha256(contents).hexdigest()}
    if commit is not None:
        origin["commit"] = commit
    return checks, origin


def prepare_policy_timelines(path, fixtures, paths, repo, commit):
    checks, origin = load_timeline_policy(path, repo, commit)
    positions = {source: index for index, source in enumerate(paths)}
    required = {"alertname", "end"}
    limits = {"max_delay", "fire_by"}
    allowed = required | limits | {"source"}
    seen = set()
    timelines = []
    remaining_ticks = MAX_TIMELINE_TICKS
    for number, check in enumerate(checks, start=1):
        try:
            if not isinstance(check, dict) or not required <= check.keys() or not limits.intersection(check):
                raise ValueError("requires alertname, end, and at least one of max_delay or fire_by")
            if check.keys() - allowed:
                raise ValueError("contains unknown fields")
            alertname = check["alertname"]
            if not isinstance(alertname, str) or not alertname.strip():
                raise ValueError("alertname must be a nonempty string")
            if "source" in check:
                source = check["source"]
                if not isinstance(source, str) or not source.strip():
                    raise ValueError("source must be a nonempty path")
                key = Path(source) if isinstance(paths[0], Path) else source
                if key not in positions:
                    raise ValueError(f"source {source!r} must match one of the supplied incident paths")
                index = positions[key]
            elif len(paths) != 1:
                raise ValueError("source is required when comparing multiple incidents")
            else:
                index = 0
            identity = (index, alertname)
            if identity in seen:
                raise ValueError(f"duplicate check for {alertname!r} in {paths[index]}")
            end = duration_ms(check["end"])
            max_delay = duration_ms(check["max_delay"]) if "max_delay" in check else None
            fire_by = duration_ms(check["fire_by"]) if "fire_by" in check else None
            timeline = prepare_timeline(fixtures[index], alertname, 0, end, max_delay,
                                        fire_by=fire_by, tick_budget=remaining_ticks)
        except ValueError as exc:
            raise ValueError(f"{path}: check {number}: {exc}") from exc
        seen.add(identity)
        timelines.append((index, timeline))
        remaining_ticks -= timeline.evaluation_ticks
    return timelines, origin


def prepare_comparison_timelines(args, fixtures, index, paths, *, repo=None, commit=None):
    if args.timeline_policy is not None:
        return prepare_policy_timelines(args.timeline_policy, fixtures, paths, repo, commit)
    if index is None:
        return (), None
    max_delay = duration_ms(args.timeline_max_delay) if args.timeline_max_delay is not None else None
    fire_by = duration_ms(args.timeline_fire_by) if args.timeline_fire_by is not None else None
    timeline = prepare_timeline(
        fixtures[index], args.timeline_alertname, 0, duration_ms(args.timeline_end), max_delay, fire_by=fire_by,
    )
    return ((index, timeline),), None


def compare_main(argv):
    parser = argparse.ArgumentParser(
        prog=f"{Path(sys.argv[0]).name} compare",
        description="Compare two rulesets against identical captured samples and alert expectations.",
    )
    parser.add_argument("fixtures", metavar="fixture", type=Path, nargs="+", help="test fixtures generated by this CLI")
    add_rule_comparison_options(parser)
    parser.add_argument(
        "--capture-summary", type=Path, action="append",
        help="verify the fixture hash against this capture summary (one per fixture, in the same order)",
    )
    add_comparison_timeline_options(parser, "fixture", path_type=Path)
    add_comparison_report_options(parser)
    args = parser.parse_args(argv)
    if args.capture_summary is not None and len(args.capture_summary) != len(args.fixtures):
        parser.error("provide one --capture-summary per incident fixture, in the same order")
    timing_index = comparison_timeline_index(parser, args, args.fixtures, args.timeline_fixture, "fixture")
    try:
        sources = load_comparison_rules(parser, args)
        fixtures = load_replay_fixtures(args.fixtures, args.capture_summary, sources.repo, sources.fixture_commit)
        timelines, policy = prepare_comparison_timelines(
            args, fixtures, timing_index, args.fixtures, repo=sources.repo, commit=sources.fixture_commit,
        )
        before_rules = comparison_rule_bytes(sources.before, args.rule_format)
        after_rules = comparison_rule_bytes(sources.after, args.rule_format)
        return compare(
            fixtures, [before_rules] * len(fixtures), after_rules, args.promtool, revisions=sources.revisions,
            gate=args.gate, json_report=args.json_report, fixture_commit=sources.fixture_commit,
            junit_report=args.junit_report, rule_paths=sources.rule_paths,
            show_rule_paths=args.before_rule_file is not None, timelines=timelines, timeline_policy=policy,
        )
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"error: {exc}\n")


def compare_bundle_main(argv):
    parser = argparse.ArgumentParser(
        prog=f"{Path(sys.argv[0]).name} compare-bundle",
        description="Use incident bundles to compare proposed rules with archived or explicitly supplied baseline rules.",
    )
    parser.add_argument("bundles", metavar="bundle", nargs="+", help="ZIP archives created with bundle (repository-root-relative in Git mode)")
    parser.add_argument("--before", type=Path, action="append", help="override the archived baseline with a local rule file (repeatable)")
    parser.add_argument("--after", type=Path, action="append", help="proposed rule file in the working tree (repeatable)")
    parser.add_argument("--bundle-ref", help="Git ref or commit containing the bundles and any explicit baseline rules")
    parser.add_argument("--after-ref", help="Git ref or commit containing the proposed rules")
    parser.add_argument("--rule-file", action="append", help="repository-root-relative proposed rule path when using archived baselines (repeatable)")
    parser.add_argument("--before-rule-file", action="append", help="repository-root-relative baseline rule path at --bundle-ref (repeatable)")
    parser.add_argument("--after-rule-file", action="append", help="repository-root-relative proposed rule path at --after-ref with an explicit baseline (repeatable)")
    parser.add_argument("--repo", type=Path, help="Git repository for ref comparison (default: current directory)")
    parser.add_argument(
        "--rule-format", choices=("prometheus", "kubernetes"), default="prometheus",
        help="input format of explicitly supplied rule files (default: prometheus)",
    )
    add_comparison_timeline_options(parser, "bundle", path_type=str)
    add_comparison_report_options(parser)
    args = parser.parse_args(argv)
    scoped_paths = args.before_rule_file is not None or args.after_rule_file is not None
    git_mode = scoped_paths or any(value is not None for value in (args.bundle_ref, args.after_ref, args.rule_file, args.repo))
    if git_mode and (args.before or args.after):
        parser.error("choose either local rule files or Git ref comparison options")
    if git_mode and not (args.bundle_ref and args.after_ref):
        parser.error("Git bundle comparison requires --bundle-ref and --after-ref")
    if scoped_paths and args.rule_file:
        parser.error("choose either --rule-file or the --before-rule-file and --after-rule-file lists")
    if scoped_paths and not (args.before_rule_file and args.after_rule_file):
        parser.error("provide both --before-rule-file and --after-rule-file lists")
    if git_mode and not (scoped_paths or args.rule_file):
        parser.error("Git bundle comparison requires --rule-file or both --before-rule-file and --after-rule-file lists")
    if not git_mode and not args.after:
        parser.error("file bundle comparison requires at least one --after rule file")
    timing_index = comparison_timeline_index(parser, args, args.bundles, args.timeline_bundle, "bundle")
    try:
        identities = args.bundles if git_mode else [os.path.realpath(path, strict=True) for path in args.bundles]
        if len(identities) != len(set(identities)):
            raise ValueError("each incident bundle must be supplied only once")
        revisions = None
        before = None
        repo = None
        include_archived_rules = not (scoped_paths or args.before)
        if git_mode:
            repo = args.repo or Path.cwd()
            revisions = (resolve_commit(repo, args.bundle_ref), resolve_commit(repo, args.after_ref))
            replays = [
                load_committed_bundle_replay(repo, revisions[0], path, include_archived_rules=include_archived_rules)
                for path in args.bundles
            ]
            candidate_paths = args.after_rule_file if scoped_paths else args.rule_file
            after = read_committed_rules(repo, revisions[1], candidate_paths)
            rule_paths = {"after": candidate_paths}
            if scoped_paths:
                before = read_committed_rules(repo, revisions[0], args.before_rule_file)
                rule_paths = {"before": args.before_rule_file, "after": candidate_paths}
        else:
            replays = [load_bundle_replay(Path(path), include_archived_rules=include_archived_rules) for path in args.bundles]
            after = read_rule_sources(args.after)
            candidate_paths = [str(path) for path in args.after]
            rule_paths = {"after": candidate_paths}
            if args.before:
                before = read_rule_sources(args.before)
                rule_paths = {"before": [str(path) for path in args.before], "after": candidate_paths}
        fixtures, baseline_rule_sets, bundles = zip(*replays)
        timelines, policy = prepare_comparison_timelines(
            args, fixtures, timing_index, args.bundles, repo=repo, commit=revisions[0] if revisions else None,
        )
        if before is not None:
            baseline_rule_sets = [comparison_rule_bytes(before, args.rule_format)] * len(fixtures)
        return compare(
            fixtures, baseline_rule_sets, comparison_rule_bytes(after, args.rule_format), args.promtool, revisions=revisions,
            gate=args.gate, json_report=args.json_report, fixture_commit=None, bundles=bundles,
            junit_report=args.junit_report, rule_paths=rule_paths, show_rule_paths=not include_archived_rules,
            timelines=timelines, timeline_policy=policy,
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
    if sys.argv[1:2] == ["timeline"]:
        return timeline_main(sys.argv[2:])
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
        "inspect --help for sample coverage, timeline --help for firing times, "
        "compare --help and compare-bundle --help for rule comparisons, "
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
