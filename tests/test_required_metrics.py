from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
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
PRIMARY = "service:requests_5"
LAST = "end_total"
OUTSIDE = "outside_total"
PRESENT = (LAST, PRIMARY)
ARTIFACT_MODES = (("generate", "fixture.test.yml"), ("snapshot", "snapshot.json"), ("bundle", "capture.zip"))


def series(name, *points, **labels):
    return {
        "metric": {"__name__": name, **labels},
        "values": [[START + point, "1"] for point in points],
    }


def matrix(*series):
    return {"status": "success", "data": {"resultType": "matrix", "result": list(series)}}


def metric_options(names):
    return tuple(option for name in names for option in ("--require-metric", name))


class RequiredMetricsIntegrationTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        self.config = self.write_json("incident.json", {
            "start": "2025-01-01T09:00:00+09:00", "end": "2025-01-01T09:00:10+09:00",
            "sample_interval": "1s", "evaluation_interval": "1s",
            "selectors": [PRIMARY, LAST], "rule_files": ["native.rules.yml"],
            "expectations": [{"at": "0s", "alertname": "Example", "alerts": [{"labels": {}}]}],
        })
        (self.workspace / "native.rules.yml").write_text(
            "groups:\n- name: synthetic\n  rules:\n  - alert: Example\n    expr: vector(1)\n", encoding="utf-8",
        )
        self.sources = (
            self.write_json("first capture.json", matrix(
                series(PRIMARY, 0, job="frontend"),
                series(PRIMARY, -0.001, job="backfill"),
                series(OUTSIDE, -0.001, 10.001),
                series("alias_only_suffix", 5, alias="alias_only"),
                series("empty_total"),
            )),
            self.write_json("second capture.json", matrix(
                series(PRIMARY, 0, job="frontend"),
                series(LAST, 10, job="edge"),
            )),
        )

    def write_json(self, filename, payload):
        path = self.workspace / filename
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def cli(self, *arguments, cwd=None):
        environment = {**os.environ, "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}
        environment.pop("PROMETHEUS_BEARER_TOKEN", None)
        return subprocess.run(
            [sys.executable, CLI, *arguments], cwd=cwd or self.workspace, env=environment,
            capture_output=True, text=True, timeout=30,
        )

    def capture(self, mode, filename=None, *options, names=(), max_gap=None, url=None):
        command = [] if mode == "generate" else [mode]
        command.append(self.config)
        if url is None:
            for source in self.sources:
                command.extend(("--matrix", source))
        else:
            command.extend(("--prometheus-url", url))
        if mode == "generate":
            command.extend(("--summary-format", "json"))
        if mode == "inspect":
            command.extend(("--format", "json"))
        output = self.workspace / filename if filename is not None else None
        if output is not None:
            command.extend(("--output", output))
        if max_gap is not None:
            command.extend(("--max-gap", max_gap))
        return self.cli(*command, *metric_options(names), *options), output

    def assert_exit(self, result, expected):
        self.assertEqual(result.returncode, expected, f"{result.stdout}\n{result.stderr}")

    def assert_no_output(self, outcome, expected, diagnostic):
        result, output = outcome
        self.assert_exit(result, expected)
        self.assertEqual(result.stdout, "")
        self.assertRegex(result.stderr, diagnostic)
        if output is not None:
            self.assertFalse(output.exists())

    def inspect_report(self, names=(), *, max_gap=None, expected=0):
        result, _ = self.capture("inspect", names=names, max_gap=max_gap)
        self.assert_exit(result, expected)
        return json.loads(result.stdout)

    def test_inspect_requires_exact_observed_metric_names_in_first_seen_order(self):
        names = ("missing_0", LAST, PRIMARY, LAST, OUTSIDE, "alias_only", "empty_total", "Service:requests_5", "missing_0")
        report = self.inspect_report(names, expected=1)

        self.assertIsNone(report["gate"])
        self.assertEqual(report["required_metrics"], {
            "names": ["missing_0", LAST, PRIMARY, OUTSIDE, "alias_only", "empty_total", "Service:requests_5"],
            "missing": ["missing_0", OUTSIDE, "alias_only", "empty_total", "Service:requests_5"],
            "passed": False,
        })
        self.assertEqual(report["series_count"], 3)
        self.assertEqual(report["sample_count"], 3)
        labels = {item["series"] for item in report["series"]}
        self.assertEqual(labels, {
            f'{PRIMARY}{{job="frontend"}}', f'{LAST}{{job="edge"}}', 'alias_only_suffix{alias="alias_only"}',
        })
        self.assertNotIn("required_metrics", self.inspect_report())

    def test_inspect_gap_and_required_metric_gates_pass_or_fail_independently(self):
        cases = (
            ("missing only", (*PRESENT, OUTSIDE), "10s", 10_000, True, [OUTSIDE], 1),
            ("gap only", PRESENT, "9999ms", 9_999, False, [], 1),
            ("both pass", PRESENT, "10s", 10_000, True, [], 0),
        )
        for name, names, limit, limit_ms, gap_passed, missing, code in cases:
            with self.subTest(case=name):
                report = self.inspect_report(names, max_gap=limit, expected=code)

                self.assertEqual(report["gate"], {"max_gap_ms": limit_ms, "passed": gap_passed})
                self.assertEqual(report["required_metrics"], {
                    "names": list(names), "missing": missing, "passed": not missing,
                })

    def test_artifact_routes_preserve_data_and_record_successful_required_metrics(self):
        expected = {"names": list(PRESENT), "missing": [], "passed": True}
        outputs = {}
        for mode, filename in ARTIFACT_MODES:
            with self.subTest(mode=mode):
                blocked = self.capture(mode, filename, names=(*PRESENT, OUTSIDE), max_gap="10s")
                self.assert_no_output(blocked, 1, rf"(?i)required metric.*{OUTSIDE}")

                baseline, baseline_path = self.capture(mode, f"baseline-{filename}")
                gated, path = self.capture(mode, filename, names=PRESENT, max_gap="10s")
                self.assert_exit(baseline, 0)
                self.assert_exit(gated, 0)
                outputs[mode] = baseline_path, path
                if mode != "bundle":
                    self.assertEqual(path.read_bytes(), baseline_path.read_bytes())
                if mode == "generate":
                    self.assertNotIn("required_metrics", json.loads(baseline.stdout))
                    self.assertEqual(json.loads(gated.stdout)["required_metrics"], expected)

        ordinary, required = outputs["bundle"]
        detached = self.workspace / "unpacked incident"
        with ZipFile(ordinary) as baseline, ZipFile(required) as bundle:
            for member in ("incident.json", "incident.matrix.json", "incident.test.yml", "rules/rules-1.yml"):
                self.assertEqual(bundle.read(member), baseline.read(member), member)
            self.assertEqual(bundle.read("incident.matrix.json"), outputs["snapshot"][1].read_bytes())
            self.assertNotIn("required_metrics", json.loads(baseline.read("capture.json")))
            self.assertNotIn("required_metrics", json.loads(baseline.read("coverage.json")))
            capture = json.loads(bundle.read("capture.json"))
            self.assertEqual(capture["required_metrics"], expected)
            coverage = json.loads(bundle.read("coverage.json"))
            self.assertEqual(coverage, self.inspect_report(PRESENT, max_gap="10s"))
            options = capture["generation_options"]
            self.assertEqual([
                options[index + 1] for index, flag in enumerate(options) if flag == "--require-metric"
            ], list(PRESENT))
            bundle.extractall(detached)

        replay = self.cli(
            "incident.json", "--matrix", "incident.matrix.json", "--output", "regenerated.test.yml",
            "--summary-format", "json", *options, cwd=detached,
        )
        self.assert_exit(replay, 0)
        self.assertEqual(json.loads(replay.stdout)["required_metrics"], expected)
        self.assertEqual((detached / "regenerated.test.yml").read_bytes(), (detached / "incident.test.yml").read_bytes())

    def test_verify_bundle_requires_metrics_from_verified_raw_capture(self):
        created, archive = self.capture("bundle", "ungated.zip")
        self.assert_exit(created, 0)
        baseline = self.cli("verify-bundle", archive, "--format", "json")
        self.assert_exit(baseline, 0)
        self.assertNotIn("coverage", json.loads(baseline.stdout))
        for names, missing in ((PRESENT, []), ((*PRESENT, OUTSIDE), [OUTSIDE])):
            with self.subTest(names=names):
                verified = self.cli("verify-bundle", archive, "--format", "json", *metric_options(names))
                exit_code = int(bool(missing))
                self.assert_exit(verified, exit_code)
                report = json.loads(verified.stdout)
                self.assertEqual(report["verified_files"], json.loads(baseline.stdout)["verified_files"])
                self.assertIsNone(report["coverage"]["gate"])
                self.assertEqual(report["coverage"], self.inspect_report(names, expected=exit_code))
        invalid = self.cli("verify-bundle", archive, "--format", "json", "--require-metric=")
        self.assert_no_output((invalid, None), 2, r"(?i)require.metric|metric name")

    @contextmanager
    def prometheus(self):
        requests = []
        data = {PRIMARY: series(PRIMARY, 0, job="frontend"), LAST: series(LAST, 10, job="edge")}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                target = urlsplit(self.path)
                params = parse_qs(target.query)
                query = re.fullmatch(r"(.+)\[(\d+)(ms|s)\]", params.get("query", [""])[0])
                if target.path != "/api/v1/query" or query is None or query[1] not in data or "time" not in params:
                    self.send_error(400, "Expected a configured range selector")
                    return
                name, span, unit = query.groups()
                width = int(span) * (1000 if unit == "s" else 1)
                instant = datetime.fromisoformat(params["time"][0].replace("Z", "+00:00"))
                right = (instant - EPOCH) // MILLISECOND
                observed = [sample for sample in data[name]["values"] if right - width < sample[0] * 1000 <= right]
                response = matrix({**data[name], "values": observed}) if observed else matrix()
                body = json.dumps(response).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_arguments):
                pass

        with HTTPServer(("127.0.0.1", 0), Handler) as service:
            thread = Thread(target=service.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            thread.start()
            try:
                host, port = service.server_address
                yield f"http://{host}:{port}", requests
            finally:
                service.shutdown()
                thread.join(timeout=5)

    def test_live_capture_checks_required_names_after_all_selectors_and_chunks(self):
        with self.prometheus() as (url, requests):
            result, output = self.capture("snapshot", "live.json", "--chunk-window", "6s", names=PRESENT, url=url)

        self.assert_exit(result, 0)
        self.assertEqual(len(requests), 4)
        self.assertEqual(json.loads(output.read_bytes()), matrix(series(LAST, 10, job="edge"), series(PRIMARY, 0, job="frontend")))

    def test_invalid_metrics_are_rejected_before_http_or_artifact(self):
        with self.prometheus() as (url, requests):
            for mode, filename in (*ARTIFACT_MODES, ("inspect", None)):
                for invalid in ("", f'{PRIMARY}{{job="frontend"}}', " trailing", "9metric"):
                    with self.subTest(mode=mode, name=invalid):
                        result = self.capture(mode, filename, names=(*PRESENT, invalid), url=url)

                        self.assert_no_output(result, 2 if mode == "inspect" else 1, r"(?i)require.metric|metric name")
        self.assertEqual(requests, [])


if __name__ == "__main__":
    unittest.main()
