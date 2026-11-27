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
START = 1_735_689_600
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
MILLISECOND = timedelta(milliseconds=1)
GAP_CASES = {
    "leading_total": (4, 7, 10),
    "interior_total": (0, 3, 7, 10),
    "trailing_total": (0, 3, 6),
}
ARTIFACT_MODES = (("generate", "incident.test.yml"), ("snapshot", "samples.json"), ("bundle", "incident.zip"))


def raw_series(metric, points):
    return {"metric": {"__name__": metric}, "values": [[START + point, str(index)] for index, point in enumerate(points)]}


def raw_matrix(*series):
    return {"status": "success", "data": {"resultType": "matrix", "result": list(series)}}


class CaptureCoverageGateIntegrationTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        self.config = self.write_json("incident.json", {
            "start": "2025-01-01T09:00:00+09:00", "end": "2025-01-01T09:00:10+09:00",
            "sample_interval": "1s", "evaluation_interval": "1s",
            "selectors": ["coverage_total"], "rule_files": ["native rules.yml"],
            "expectations": [{"at": "0s", "alertname": "Example", "alerts": [{"labels": {}}]}],
        })
        (self.workspace / "native rules.yml").write_text(
            "groups:\n- name: synthetic\n  rules:\n  - alert: Example\n    expr: vector(1)\n", encoding="utf-8",
        )

    def write_json(self, name, document):
        path = self.workspace / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def cli(self, *arguments, cwd=None):
        environment = {**os.environ, "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}
        environment.pop("PROMETHEUS_BEARER_TOKEN", None)
        return subprocess.run(
            [sys.executable, CLI, *arguments], cwd=cwd or self.workspace, env=environment,
            capture_output=True, text=True, timeout=30,
        )

    def capture(self, mode, filename, *options, source=None, url=None, max_gap=None):
        output = self.workspace / filename
        command = [] if mode == "generate" else [mode]
        command.extend((self.config, "--output", output, *options))
        if mode == "generate":
            command.extend(("--summary-format", "json"))
        if url is not None:
            command.extend(("--prometheus-url", url))
        else:
            command.extend(("--matrix", source))
        if max_gap is not None:
            command.append(f"--max-gap={max_gap}")
        return self.cli(*command), output

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")

    def assert_failure(self, outcome, diagnostic=r"(?i)gap|coverage"):
        result, output = outcome
        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(result.stdout, "")
        self.assertRegex(result.stderr, diagnostic)
        self.assertFalse(output.exists())

    def test_each_gap_category_independently_prevents_all_artifacts(self):
        for metric, points in GAP_CASES.items():
            source = self.write_json(f"{metric}.json", raw_matrix(raw_series(metric, points)))
            for mode, filename in ARTIFACT_MODES:
                with self.subTest(metric=metric, mode=mode):
                    outcome = self.capture(mode, filename, source=source, max_gap="3999ms")

                    self.assert_failure(outcome, rf"(?i)largest gap is 4s in {metric}")

    def test_exact_limit_preserves_replay_data_and_records_gate_metadata(self):
        source = self.write_json("raw.json", raw_matrix(*(raw_series(metric, points) for metric, points in GAP_CASES.items())))
        limit = "4000ms"
        gate = {"max_gap_ms": 4_000, "passed": True}
        outputs = {}
        for mode, filename in ARTIFACT_MODES:
            with self.subTest(mode=mode):
                baseline, baseline_path = self.capture(mode, f"baseline-{filename}", source=source)
                gated, gated_path = self.capture(mode, f"gated-{filename}", source=source, max_gap=limit)

                self.assert_success(baseline)
                self.assert_success(gated)
                if mode != "bundle":
                    self.assertEqual(gated_path.read_bytes(), baseline_path.read_bytes())
                if mode == "generate":
                    self.assertNotIn("coverage_gate", json.loads(baseline.stdout))
                    self.assertEqual(json.loads(gated.stdout)["coverage_gate"], gate)
                outputs[mode] = (baseline_path, gated_path)

        inspect = self.cli("inspect", self.config, "--matrix", source, "--format", "json", "--max-gap", limit)
        self.assert_success(inspect)
        bundle_without_gate, bundle_with_gate = outputs["bundle"]
        destination = self.workspace / "detached capture"
        with ZipFile(bundle_without_gate) as baseline, ZipFile(bundle_with_gate) as gated:
            self.assertNotIn("coverage_gate", json.loads(baseline.read("capture.json")))
            self.assertIsNone(json.loads(baseline.read("coverage.json"))["gate"])
            for name in ("incident.json", "incident.test.yml", "incident.matrix.json", "rules/rules-1.yml"):
                self.assertEqual(gated.read(name), baseline.read(name))
            self.assertEqual(gated.read("incident.matrix.json"), outputs["snapshot"][1].read_bytes())
            coverage = json.loads(gated.read("coverage.json"))
            self.assertEqual(coverage, json.loads(inspect.stdout))
            self.assertEqual(coverage["gate"], gate)
            by_series = {row["series"]: row for row in coverage["series"]}
            self.assertEqual(by_series["leading_total"]["leading_gap_ms"], 4_000)
            self.assertEqual(by_series["interior_total"]["max_sample_gap"]["duration_ms"], 4_000)
            self.assertEqual(by_series["trailing_total"]["trailing_gap_ms"], 4_000)
            self.assertTrue(all(row["gap_exceeded"] is False for row in by_series.values()))
            capture_summary = json.loads(gated.read("capture.json"))
            self.assertEqual(capture_summary["generation_options"], ["--max-gap", limit])
            self.assertEqual(capture_summary["coverage_gate"], gate)
            gated.extractall(destination)

        replay = self.cli(
            "incident.json", "--matrix", "incident.matrix.json", "--output", "regenerated.test.yml",
            "--summary-format", "json", *capture_summary["generation_options"], cwd=destination,
        )
        self.assert_success(replay)
        self.assertEqual(json.loads(replay.stdout)["coverage_gate"], gate)
        self.assertEqual((destination / "regenerated.test.yml").read_bytes(), (destination / "incident.test.yml").read_bytes())

    def test_no_observed_samples_fails_the_artifact_gate(self):
        source = self.write_json("outside capture.json", raw_matrix(raw_series("outside_total", (-0.001, 10.001))))
        for mode, filename in ARTIFACT_MODES:
            with self.subTest(mode=mode):
                self.assert_failure(
                    self.capture(mode, filename, source=source, max_gap="10s"), r"(?i)max-gap.*no float samples",
                )

    def test_submillisecond_utc_offset_is_rejected(self):
        config = json.loads(self.config.read_text(encoding="utf-8"))
        config["start"] = "2025-01-01T09:00:00+09:00:00.000100"
        config["end"] = "2025-01-01T09:00:10+09:00:00.000200"
        self.write_json(self.config.name, config)
        source = self.write_json("raw.json", raw_matrix(raw_series("coverage_total", (0, 5, 10))))
        for mode, filename in ARTIFACT_MODES:
            with self.subTest(mode=mode):
                self.assert_failure(self.capture(mode, filename, source=source, max_gap="5s"), "millisecond precision")

    def test_rounding_cannot_hide_a_gap_in_the_original_samples(self):
        source = self.write_json("off-grid.json", raw_matrix(raw_series("coverage_total", (0.001, 4.002, 7, 10))))
        gate = {"max_gap_ms": 4_001, "passed": True}
        for mode, filename in ((mode, path) for mode, path in ARTIFACT_MODES if mode != "snapshot"):
            with self.subTest(mode=mode):
                self.assert_failure(self.capture(mode, filename, "--round-up", source=source, max_gap="4s"))
                result, path = self.capture(mode, filename, "--round-up", source=source, max_gap="4001ms")

                self.assert_success(result)
                if mode == "generate":
                    summary = json.loads(result.stdout)
                else:
                    with ZipFile(path) as archive:
                        summary = json.loads(archive.read("capture.json"))
                        series, = json.loads(archive.read("coverage.json"))["series"]
                        self.assertEqual(series["leading_gap_ms"], 1)
                        self.assertEqual(series["max_sample_gap"]["duration_ms"], 4_001)
                        recorded, = json.loads(archive.read("incident.matrix.json"), parse_float=Decimal)["data"]["result"]
                        self.assertEqual(recorded["values"][:2], [
                            [Decimal(START) + Decimal("0.001"), "0"], [Decimal(START) + Decimal("4.002"), "1"],
                        ])
                self.assertEqual(summary["shifted_sample_count"], 2)
                self.assertEqual(summary["max_shift_ms"], 999)
                self.assertEqual(summary["coverage_gate"], gate)

    @contextmanager
    def prometheus(self):
        requests = []
        series = raw_series("coverage_total", GAP_CASES["interior_total"])

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                target = urlsplit(self.path)
                params = parse_qs(target.query)
                query = re.fullmatch(r"coverage_total\[(\d+)(ms|s)\]", params.get("query", [""])[0])
                if target.path != "/api/v1/query" or query is None or "time" not in params:
                    self.send_error(400, "Expected a range selector capture")
                    return
                width, unit = query.groups()
                width_ms = int(width) * (1000 if unit == "s" else 1)
                instant = datetime.fromisoformat(params["time"][0].replace("Z", "+00:00"))
                right = (instant - EPOCH) // MILLISECOND
                values = [
                    point for point in series["values"] if right - width_ms < point[0] * 1000 <= right
                ]
                response = raw_matrix({**series, "values": values}) if values else raw_matrix()
                content = json.dumps(response).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)

            def log_message(self, *_arguments):
                pass

        with HTTPServer(("127.0.0.1", 0), Handler) as server:
            worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            worker.start()
            try:
                host, port = server.server_address
                yield f"http://{host}:{port}", requests
            finally:
                server.shutdown()
                worker.join(timeout=5)

    def test_live_chunks_share_one_coverage_gate_across_chunk_boundaries(self):
        with self.prometheus() as (url, requests):
            for mode, filename in ARTIFACT_MODES:
                with self.subTest(mode=mode):
                    before = len(requests)
                    blocked = self.capture(mode, filename, "--chunk-window", "3s", url=url, max_gap="3999ms")

                    self.assert_failure(blocked)
                    self.assertEqual(len(requests) - before, 4)
                    before = len(requests)
                    allowed, path = self.capture(mode, filename, "--chunk-window", "3s", url=url, max_gap="4s")

                    self.assert_success(allowed)
                    self.assertTrue(path.is_file())
                    self.assertEqual(len(requests) - before, 4)

    def test_invalid_limit_is_rejected_before_any_live_requests(self):
        with self.prometheus() as (url, requests):
            for mode, filename in ARTIFACT_MODES:
                for limit in ("0s", "-1ms", "soon"):
                    with self.subTest(mode=mode, limit=limit):
                        self.assert_failure(
                            self.capture(mode, filename, url=url, max_gap=limit), r"(?i)max.gap|duration|positive",
                        )
        self.assertEqual(requests, [])


if __name__ == "__main__":
    unittest.main()
