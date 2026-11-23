#!/usr/bin/env python3
"""Create an offline promtool rule test from historical float samples."""

import argparse
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import json
import math
import os
from pathlib import Path
import re
import sys
from tempfile import NamedTemporaryFile
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen


EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
DURATION_PART = re.compile(r"(\d+)(ms|s|m|h|d)", re.ASCII)
UNIT_MS = {"ms": 1, "s": 1_000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}
METRIC_NAME = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
LABEL_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")
SELECTOR = re.compile(r'(?:[a-zA-Z_:][a-zA-Z0-9_:]*)?(?:\{(?:[^{}"\\]|"(?:[^"\\]|\\.)*")*\})?')
FLOAT = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", re.ASCII)
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
                if slot in slots and slots[slot] != (offset, value):
                    raise ValueError("multiple samples land in one fixture slot; choose a finer sample_interval")
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
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
    main()
