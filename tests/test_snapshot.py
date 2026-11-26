from decimal import Decimal
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Thread
import unittest
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
START = 1_735_689_600


def matrix(*series):
    return {"status": "success", "data": {"resultType": "matrix", "result": list(series)}}


def metric(name, values, **labels):
    return {"metric": {"__name__": name, **labels}, "values": values}


class SnapshotIntegrationTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        self.window = {"start": "2025-01-01T00:00:00Z", "end": "2025-01-01T00:10:00Z"}

    def write_json(self, name, value):
        path = self.workspace / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def snapshot(self, name, *options, config=None, env=None):
        capture_config = self.write_json("snapshot config.json", self.window if config is None else config)
        output = self.workspace / name
        result = subprocess.run(
            [sys.executable, CLI, "snapshot", capture_config, "--output", output, *options],
            cwd=self.workspace, env=env, capture_output=True, text=True, timeout=30,
        )
        return result, output

    def generate_fixture(self, name, config, *raw_inputs):
        replay_config = self.write_json("replay config.json", config)
        output = self.workspace / name
        command = [
            sys.executable, CLI, replay_config, "--rule-file", DEMO / "after.rules.yml", "--output", output,
        ]
        for raw_input in raw_inputs:
            command.extend(("--matrix", raw_input))
        result = subprocess.run(command, cwd=self.workspace, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        return output

    def assert_snapshot_failed(self, result, output, diagnostic):
        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertRegex(result.stderr, diagnostic)
        self.assertFalse(output.exists())

    def test_saved_matrices_merge_and_preserve_boundaries_and_millisecond_numbers(self):
        first = self.write_json("first.json", matrix(
            metric("z_total", [[START + 600, "2e0"], [START + 0.005, "1.234e+0"], [START - 0.001, "0"]], env="prod"),
            metric("a_total", [[START + 0.001, "-1.00"], [START, "-2"], [START + 600.001, "99"]], site="test"),
        ))
        second = self.write_json("second.json", matrix({
            "metric": {"env": "prod", "__name__": "z_total"},
            "values": [[START + 0.005, "1.234"], [START + 0.002, "1.00"], [START + 600, "2.0"]],
        }))

        result, output = self.snapshot("merged raw.json", "--matrix", first, "--matrix", second)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        recorded = json.loads(output.read_text(encoding="utf-8"), parse_float=Decimal)
        self.assertEqual(recorded, matrix(
            metric("a_total", [[START, "-2"], [Decimal("1735689600.001"), "-1.00"]], site="test"),
            metric("z_total", [
                [Decimal("1735689600.002"), "1.00"], [Decimal("1735689600.005"), "1.234e+0"], [START + 600, "2e0"],
            ], env="prod"),
        ))

    def test_fractional_timestamps_are_exact_across_the_unix_epoch(self):
        window = {"start": "1969-12-31T23:59:59.998Z", "end": "1970-01-01T00:00:00.001Z"}
        source = self.write_json("epoch.json", matrix(metric("n_total", [[-0.002, "1"], [-0.001, "2"], [0, "3"], [0.001, "4"]])))

        result, output = self.snapshot("epoch raw.json", "--matrix", source, config=window)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        recorded = json.loads(output.read_text(encoding="utf-8"), parse_float=Decimal)
        self.assertEqual(recorded, matrix(metric("n_total", [
            [Decimal("-0.002"), "1"], [Decimal("-0.001"), "2"], [0, "3"], [Decimal("0.001"), "4"],
        ])))

    def test_live_snapshot_repeats_raw_queries_and_replays_off_grid_samples(self):
        selectors = ['payment_http_requests_total{code="500"}', 'payment_http_requests_total{code=~"500|200"}']
        first = json.loads((DEMO / "incident.matrix.json").read_text(encoding="utf-8"))
        second = matrix(metric("payment_http_requests_total", [[START + 5.25, "0.0"], [START + 30, "0.00"]], code="500"))
        responses = (first, second)
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                target = urlsplit(self.path)
                request_number = len(requests)
                requests.append((target.path, parse_qs(target.query), self.headers.get("Authorization")))
                if request_number >= len(responses):
                    self.send_error(404)
                    return
                body = json.dumps(responses[request_number]).encode("utf-8")
                self.send_response(200)
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
                env = {**os.environ, "NO_PROXY": host, "no_proxy": host, "PROMETHEUS_BEARER_TOKEN": "local-test-token"}
                result, captured = self.snapshot(
                    "live raw.json", "--prometheus-url", f"http://{host}:{port}/prometheus",
                    config={**self.window, "selectors": selectors}, env=env,
                )
            finally:
                server.shutdown()
                worker.join(timeout=5)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(requests, [
            ("/prometheus/api/v1/query",
             {"query": [f"{selector}[600001ms]"], "time": ["2025-01-01T00:10:00+00:00"]},
             "Bearer local-test-token")
            for selector in selectors
        ])
        recorded = json.loads(captured.read_text(encoding="utf-8"), parse_float=Decimal)
        self.assertEqual(recorded["data"]["result"][0]["values"][1], [Decimal("1735689605.25"), "0.0"])

        replay = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        replay["sample_interval"] = "auto"
        source_paths = [self.write_json(f"response-{index}.json", response) for index, response in enumerate(responses)]
        direct = self.generate_fixture("direct.test.yml", replay, *source_paths)
        offline = self.generate_fixture("offline.test.yml", replay, captured)
        self.assertEqual(offline.read_bytes(), direct.read_bytes())
        group, = json.loads(offline.read_text(encoding="utf-8"))["tests"]
        self.assertEqual(group["interval"], "750ms")
        sample_series, = group["input_series"]
        self.assertEqual(sample_series["values"].split()[:5], ["0", "_x6", "0.0", "_x32", "0"])

    def test_existing_snapshot_is_preserved_on_repeat(self):
        original = self.write_json("original.json", matrix(metric("n_total", [[START, "1"]])))
        changed = self.write_json("changed.json", matrix(metric("n_total", [[START, "2"]])))
        first, output = self.snapshot("protected.json", "--matrix", original)
        self.assertEqual(first.returncode, 0, f"{first.stdout}\n{first.stderr}")
        original_bytes = output.read_bytes()
        original_inode = output.stat().st_ino

        second, _ = self.snapshot(output.name, "--matrix", changed)

        self.assertEqual(second.returncode, 1, f"{second.stdout}\n{second.stderr}")
        self.assertRegex(second.stderr, r"(?i)exist|overwrite")
        self.assertEqual(output.read_bytes(), original_bytes)
        self.assertEqual(output.stat().st_ino, original_inode)

    def test_invalid_later_response_does_not_write_partial_snapshot(self):
        good = matrix(metric("n_total", [[START, "1"]]))
        first = self.write_json("usable.json", good)
        invalid = (
            ("conflict", matrix(metric("n_total", [[START, "2"]])), r"(?i)conflict"),
            ("warning", {**good, "warnings": ["could not query every replica"]}, r"(?i)warning|capture"),
            ("histogram", matrix({
                "metric": {"__name__": "latency"},
                "histograms": [[START, {"count": "1", "sum": "1", "buckets": []}]],
            }), r"(?i)histogram"),
            ("non-finite", matrix(metric("n_total", [[START + 1, "NaN"]])), r"(?i)finite"),
            ("vector", {"status": "success", "data": {"resultType": "vector", "result": []}}, r"(?i)matrix"),
            ("string-row", matrix(metric("n_total", ["12"])), r"(?i)sample|row|values"),
            ("object-values", matrix(metric("n_total", {"12": "2"})), r"(?i)sample|array|list|values"),
        )
        for name, response, diagnostic in invalid:
            with self.subTest(response=name):
                second = self.write_json(f"{name}.json", response)
                result, output = self.snapshot(f"{name} raw.json", "--matrix", first, "--matrix", second)

                self.assert_snapshot_failed(result, output, diagnostic)

    def test_all_samples_outside_window_are_rejected(self):
        outside = self.write_json("outside.json", matrix(metric("n_total", [[START - 1, "1"], [START + 601, "2"]])))

        result, output = self.snapshot("empty raw.json", "--matrix", outside)

        self.assert_snapshot_failed(result, output, r"(?i)no.*sample|empty")


if __name__ == "__main__":
    unittest.main()
