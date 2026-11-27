from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from threading import Thread
import unittest
from urllib.parse import parse_qs, urlsplit
from zipfile import ZipFile


CLI = Path(__file__).resolve().parents[1] / "incident_to_promtool.py"
START_MS = 1_735_689_600_001
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
MILLISECOND = timedelta(milliseconds=1)
TOKEN = "test-chunk-client"
EXACT = 'payment_requests_total{code="500"}'
WIDE = 'payment_requests_total{code=~"200|500"}'
SELECTORS = (EXACT, WIDE)
QUERY = re.compile(r"(.+)\[(\d+)(ms|s)\]")
SAMPLE_LIMIT = "query processing would load too many samples into memory in query execution"
POINTS = ((-1, "-1"), (0, "0.00"), (1, "1"), (2, "2"), (3, "3"), (5, "5"), (9, "9e0"), (10, "10"), (11, "11"))
OTHER_POINTS = ((0, "2"), (10, "2.0"))
CAPTURE_MODES = (
    ("snapshot", "matrix.json", 1),
    ("generate", "incident.test.yml", 1),
    ("inspect", None, 2),
    ("bundle", "incident.zip", 1),
)


def matrix(series):
    return {"status": "success", "data": {"resultType": "matrix", "result": series}}


def sample_limit_error():
    return 422, {"status": "error", "errorType": "execution", "error": f"{SAMPLE_LIMIT}: details for {TOKEN}"}


class ChunkedCaptureIntegrationTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        self.config = self.workspace / "incident window.json"
        self.config.write_text(json.dumps({
            "start": "2025-01-01T09:00:00.001+09:00",
            "end": "2025-01-01T09:00:00.011+09:00",
            "sample_interval": "auto",
            "evaluation_interval": "1ms",
            "selectors": list(SELECTORS),
            "rule_files": ["rules.yml"],
            "expectations": [{"at": "0s", "alertname": "Example", "alerts": [{"labels": {}}]}],
        }), encoding="utf-8")
        (self.workspace / "rules.yml").write_text(
            "groups:\n- name: synthetic\n  interval: 1ms\n  rules:\n  - alert: Example\n    expr: vector(1)\n",
            encoding="utf-8",
        )
        self.token = self.workspace / "bearer.secret"
        self.token.write_text(f"{TOKEN}\n", encoding="ascii")
        self.offline = self.workspace / "offline matrix.json"
        self.offline.write_text(json.dumps(matrix([])), encoding="utf-8")

    @contextmanager
    def server(self, *, fail_at=None, warning=False, error_for=None):
        requests = []
        shared_in_wide = tuple((offset, "3.000" if offset == 3 else value) for offset, value in POINTS)
        data = {EXACT: (("500", POINTS),), WIDE: (("500", shared_in_wide), ("200", OTHER_POINTS))}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                target = urlsplit(self.path)
                params = parse_qs(target.query)
                matched = QUERY.fullmatch(params.get("query", [""])[0])
                if target.path != "/prom/api/v1/query" or matched is None or matched[1] not in data or "time" not in params:
                    self.send_error(400, "Expected a configured range selector and evaluation time")
                    return
                selector, length, unit = matched.groups()
                width = int(length) * (1000 if unit == "s" else 1)
                instant = datetime.fromisoformat(params["time"][0].replace("Z", "+00:00"))
                right = (instant - EPOCH) // MILLISECOND - START_MS
                left = right - width
                series = []
                for code, points in data[selector]:
                    values = [[(START_MS + offset) / 1000, value] for offset, value in points if left < offset <= right]
                    if values:
                        series.append({"metric": {"__name__": "payment_requests_total", "code": code}, "values": values})
                count = sum(len(item["values"]) for item in series)
                requests.append((selector, right, width, self.headers.get("Authorization"), count))
                status, response = 200, matrix(series)
                if len(requests) == fail_at:
                    if warning:
                        response["warnings"] = ["one replica did not provide every sample"]
                    else:
                        status, response = 503, {"status": "error", "error": "cannot retrieve this capture chunk"}
                if error_for is not None:
                    error = error_for(selector, right, width)
                    if error is not None:
                        status, response = error
                body = json.dumps(response).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_arguments):
                pass

        with HTTPServer(("127.0.0.1", 0), Handler) as server:
            worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            worker.start()
            try:
                host, port = server.server_address
                yield f"http://{host}:{port}/prom", requests
            finally:
                server.shutdown()
                worker.join(timeout=5)

    def cli(self, *arguments, cwd=None):
        environment = {**os.environ, "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}
        environment.pop("PROMETHEUS_BEARER_TOKEN", None)
        return subprocess.run(
            [sys.executable, CLI, *arguments], cwd=cwd or self.workspace, env=environment,
            capture_output=True, text=True, timeout=30,
        )

    def capture(self, mode, name, *, url=None, chunk=None, split_on_limit=False):
        command = [] if mode == "generate" else [mode]
        command.append(self.config)
        if url is None:
            command.extend(("--matrix", self.offline))
        else:
            command.extend(("--prometheus-url", url, "--bearer-token-file", self.token))
        if chunk is not None:
            command.append(f"--chunk-window={chunk}")
        if split_on_limit:
            command.append("--split-on-limit")
        if mode == "inspect":
            command.extend(("--format", "json", "--max-gap", "10ms"))
        output = self.workspace / name if name is not None else None
        if output is not None:
            command.extend(("--output", output))
        return self.cli(*command), output

    def assert_ranges(self, requests, ranges):
        self.assertEqual(len(requests), len(SELECTORS) * len(ranges))
        for selector in SELECTORS:
            self.assertEqual(
                [(right, width) for query_selector, right, width, _, _ in requests if query_selector == selector],
                ranges,
            )
        self.assertEqual({authorization for _, _, _, authorization, _ in requests}, {f"Bearer {TOKEN}"})

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")

    def assert_failure(self, outcome, exit_code, diagnostic):
        result, output = outcome
        self.assertEqual(result.returncode, exit_code, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(result.stdout, "")
        self.assertRegex(result.stderr, diagnostic)
        self.assertNotIn(TOKEN, result.stderr)
        if output is not None:
            self.assertFalse(output.exists())

    def test_all_live_routes_match_unchunked_capture_with_sparse_overlapping_series(self):
        for mode, filename, _ in CAPTURE_MODES:
            with self.subTest(mode=mode):
                with self.server() as (url, requests):
                    normal, normal_file = self.capture(mode, f"normal-{filename}" if filename else None, url=url)
                self.assert_success(normal)
                self.assert_ranges(requests, [(10, 11)])

                with self.server() as (url, requests):
                    split, split_file = self.capture(mode, f"split-{filename}" if filename else None, url=url, chunk="3ms")
                self.assert_success(split)
                self.assert_ranges(requests, [(2, 3), (5, 3), (8, 3), (10, 2)])
                self.assertEqual([count for _, offset, _, _, count in requests if offset == 8], [0, 0])

                self.assert_matches_unchunked(mode, (normal, normal_file), (split, split_file))

    def assert_matches_unchunked(self, mode, baseline, recovered):
        normal, normal_file = baseline
        split, split_file = recovered
        if mode == "inspect":
            report = json.loads(split.stdout)
            self.assertEqual(report, json.loads(normal.stdout))
            self.assertEqual((report["series_count"], report["sample_count"]), (2, 9))
            self.assertEqual(report["gate"], {"max_gap_ms": 10, "passed": True})
        elif mode == "bundle":
            self.assert_bundle_matches_and_replays(normal_file, split_file)
        else:
            self.assertEqual(split_file.read_bytes(), normal_file.read_bytes())
            if mode == "snapshot":
                self.assert_snapshot_samples(split_file)
            if mode == "generate":
                group, = json.loads(split_file.read_bytes())["tests"]
                self.assertEqual(group["interval"], "1ms")
                self.assertEqual(len(group["input_series"]), 2)

    def assert_snapshot_samples(self, path):
        series = json.loads(path.read_bytes(), parse_float=Decimal)["data"]["result"]
        by_code = {entry["metric"]["code"]: entry["values"] for entry in series}
        self.assertEqual(by_code, {
            code: [[Decimal(START_MS + offset) / 1000, value] for offset, value in points if 0 <= offset <= 10]
            for code, points in (("500", POINTS), ("200", OTHER_POINTS))
        })

    def assert_bundle_matches_and_replays(self, normal_file, split_file):
        destination = self.workspace / "detached split capture"
        destination.mkdir()
        with ZipFile(normal_file) as baseline, ZipFile(split_file) as split:
            self.assertEqual(split.namelist(), baseline.namelist())
            for name in split.namelist():
                self.assertEqual(split.read(name), baseline.read(name), name)
            split.extractall(destination)
        replay = self.cli(
            "incident.json", "--matrix", "incident.matrix.json", "--output", "regenerated.test.yml", cwd=destination,
        )
        self.assert_success(replay)
        self.assertEqual((destination / "regenerated.test.yml").read_bytes(),
                         (destination / "incident.test.yml").read_bytes())

    def test_equal_nominal_window_keeps_tail_and_full_width_needs_one_query(self):
        cases = (
            ("10ms", [(9, 10), (10, 1)]),
            ("11ms", [(10, 11)]),
            ("1s", [(10, 11)]),
        )
        for chunk, ranges in cases:
            with self.subTest(chunk=chunk):
                with self.server() as (url, requests):
                    result, output = self.capture("snapshot", f"cap-{chunk}.json", url=url, chunk=chunk)
                self.assert_success(result)
                self.assert_ranges(requests, ranges)
                self.assert_snapshot_samples(output)

    def test_later_chunk_http_failure_or_warning_leaves_no_output(self):
        for warning in (False, True):
            for mode, filename, exit_code in CAPTURE_MODES:
                with self.subTest(mode=mode, warning=warning):
                    with self.server(fail_at=3, warning=warning) as (url, requests):
                        outcome = self.capture(mode, f"failed-{filename}" if filename else None, url=url, chunk="3ms")

                    diagnostic = r"(?i)warning" if warning else r"Prometheus chunk ending .*HTTP 503"
                    self.assert_failure(outcome, exit_code, diagnostic)
                    self.assertEqual(len(requests), 3)

    def test_invalid_live_chunk_or_offline_conflict_fails_before_capture(self):
        with self.server() as (url, requests):
            for mode, filename, exit_code in CAPTURE_MODES:
                with self.subTest(mode=mode):
                    output = f"invalid-{filename}" if filename else None
                    self.assert_failure(
                        self.capture(mode, output, url=url, chunk="0s"), exit_code, r"(?i)chunk.window.*positive",
                    )
                    self.assert_failure(
                        self.capture(mode, output, url=url, chunk="soon"), exit_code, r"(?i)invalid duration|chunk.window",
                    )
                    self.assert_failure(
                        self.capture(mode, output, chunk="3ms"), 2, r"(?i)chunk.window.*prometheus.url",
                    )
                    self.assert_failure(
                        self.capture(mode, output, split_on_limit=True), 2, r"(?i)split.on.limit.*prometheus.url",
                    )
        self.assertEqual(requests, [])

    def test_sample_limit_splitting_recovers_the_same_capture_on_all_live_routes(self):
        def limit(_selector, _right, width):
            return sample_limit_error() if width > 3 else None

        expected = [(10, 11), (4, 5), (1, 2), (4, 3), (10, 6), (7, 3), (10, 3)]
        for mode, filename, _ in CAPTURE_MODES:
            with self.subTest(mode=mode):
                with self.server() as (url, _):
                    baseline = self.capture(mode, f"full-{filename}" if filename else None, url=url)
                self.assert_success(baseline[0])

                with self.server(error_for=limit) as (url, requests):
                    recovered = self.capture(
                        mode, f"recovered-{filename}" if filename else None, url=url, split_on_limit=True,
                    )

                self.assert_success(recovered[0])
                self.assert_ranges(requests, expected)
                self.assert_matches_unchunked(mode, baseline, recovered)

    def test_splitting_composes_with_the_initial_range_cap(self):
        def limit(_selector, _right, width):
            return sample_limit_error() if width > 3 else None

        with self.server(error_for=limit) as (url, requests):
            result, output = self.capture("snapshot", "capped and adaptive.json", url=url, chunk="5ms", split_on_limit=True)

        self.assert_success(result)
        self.assert_ranges(requests, [(4, 5), (1, 2), (4, 3), (9, 5), (6, 2), (9, 3), (10, 1)])
        self.assert_snapshot_samples(output)

    def test_default_capture_fails_without_splitting_a_sample_limit_response(self):
        with self.server(error_for=lambda *_query: sample_limit_error()) as (url, requests):
            outcome = self.capture("snapshot", "no adaptive splitting.json", url=url)

        self.assert_failure(outcome, 1, r"HTTP 422.*too many samples")
        self.assertEqual([request[:4] for request in requests], [(EXACT, 10, 11, f"Bearer {TOKEN}")])

    def test_nonlimit_responses_never_trigger_splitting(self):
        _, canonical = sample_limit_error()
        unrelated = (
            ("unauthorized", 401, canonical, r"HTTP 401"),
            ("timed out", 503, {**canonical, "errorType": "timeout", "error": "query timed out"}, r"HTTP 503"),
            ("wrong error type", 422, {**canonical, "errorType": "timeout"}, r"HTTP 422"),
            ("wrong status field", 422, {**canonical, "status": "success"}, r"HTTP 422"),
            ("wrong response shape", 422, [canonical], r"HTTP 422"),
            ("other execution failure", 422, {**canonical, "error": "query execution failed"}, r"HTTP 422"),
            ("nonprefix error", 422, {**canonical, "error": f"simulated error text: {SAMPLE_LIMIT}"}, r"HTTP 422"),
            ("near match", 422, {**canonical, "error": f"{SAMPLE_LIMIT}extra"}, r"HTTP 422"),
            ("success status code", 200, canonical, r"(?i)capture failed"),
        )
        for name, status, response, diagnostic in unrelated:
            with self.subTest(case=name):
                with self.server(error_for=lambda *_query: (status, response)) as (url, requests):
                    outcome = self.capture("snapshot", f"{name}.json", url=url, split_on_limit=True)

                self.assert_failure(outcome, 1, diagnostic)
                self.assertEqual([request[:4] for request in requests], [(EXACT, 10, 11, f"Bearer {TOKEN}")])

    def test_sample_limit_at_one_millisecond_stops_without_partial_capture(self):
        def limit(_selector, right, width):
            return sample_limit_error() if right - width < 9 <= right else None

        expected = [(10, 11), (4, 5), (10, 6), (7, 3), (10, 3), (8, 1), (10, 2), (9, 1)]
        for mode, filename, exit_code in CAPTURE_MODES:
            with self.subTest(mode=mode):
                with self.server(error_for=limit) as (url, requests):
                    outcome = self.capture(
                        mode, f"terminal-{filename}" if filename else None, url=url, split_on_limit=True,
                    )

                self.assert_failure(outcome, exit_code, r"(?i)exceeds the sample limit even at 1ms")
                self.assertEqual(
                    [request[:4] for request in requests],
                    [(EXACT, right, width, f"Bearer {TOKEN}") for right, width in expected],
                )


if __name__ == "__main__":
    unittest.main()
