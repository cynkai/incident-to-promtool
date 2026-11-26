from datetime import datetime
from html import unescape
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CLI = Path(__file__).resolve().parents[1] / "incident_to_promtool.py"
START = 1_735_689_600


def matrix(*series):
    return {"status": "success", "data": {"resultType": "matrix", "result": list(series)}}


def metric(name, *offsets, **labels):
    return {
        "metric": {"__name__": name, **labels},
        "values": [[START + offset, "1"] for offset in offsets],
    }


class InspectCaptureIntegrationTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        self.config = self.workspace / "capture window.json"
        self.config.write_text(json.dumps({
            "start": "2025-01-01T09:00:00+09:00", "end": "2025-01-01T09:00:10+09:00",
        }), encoding="utf-8")

    def inspect(self, *responses, output_format="json", max_gap=None):
        command = [sys.executable, CLI, "inspect", self.config]
        if output_format is not None:
            command.extend(("--format", output_format))
        if max_gap is not None:
            command.extend(("--max-gap", max_gap))
        for index, response in enumerate(responses):
            path = self.workspace / f"response-{index}.json"
            path.write_text(json.dumps(response), encoding="utf-8")
            command.extend(("--matrix", path))
        return subprocess.run(command, cwd=self.workspace, capture_output=True, text=True, timeout=30)

    def assert_json(self, result, code):
        self.assertEqual(result.returncode, code, f"{result.stdout}\n{result.stderr}")
        report = json.loads(result.stdout)
        self.assertIs(type(report["schema_version"]), int)
        self.assertEqual(report["schema_version"], 1)
        return report

    def assert_utc(self, value, expected):
        self.assertTrue(value.endswith(("Z", "+00:00")), value)
        actual = datetime.fromisoformat(value.replace("Z", "+00:00"))
        self.assertEqual(actual, datetime.fromisoformat(f"2025-01-01T{expected}+00:00"))

    def test_sorted_unique_samples_report_precise_gaps_and_earliest_tie(self):
        first = matrix(
            metric("z_total", 6.25, 0.25, 10.001, region="kr", job="payment"),
            metric("a_total", 0),
            metric("outside", -0.001, 11),
        )
        second = matrix({
            "metric": {"job": "payment", "__name__": "z_total", "region": "kr"},
            "values": [[START + 3.25, "1"], [START + 0.25, "1.0"]],
        })

        report = self.assert_json(self.inspect(first, second), 0)

        self.assert_utc(report["start"], "00:00:00")
        self.assert_utc(report["end"], "00:00:10")
        self.assertEqual(report["series_count"], 2)
        self.assertEqual(report["sample_count"], 4)
        self.assertIsNone(report["gate"])
        single, repeated = report["series"]
        self.assertEqual(single["series"], "a_total")
        self.assertEqual(single["sample_count"], 1)
        self.assert_utc(single["first_sample"], "00:00:00")
        self.assertEqual(single["last_sample"], single["first_sample"])
        self.assertEqual(single["leading_gap_ms"], 0)
        self.assertEqual(single["trailing_gap_ms"], 10_000)
        self.assertIsNone(single["max_sample_gap"])
        self.assertNotIn("gap_exceeded", single)
        self.assertEqual(repeated["series"], 'z_total{job="payment",region="kr"}')
        self.assertEqual(repeated["sample_count"], 3)
        self.assert_utc(repeated["first_sample"], "00:00:00.250")
        self.assert_utc(repeated["last_sample"], "00:00:06.250")
        self.assertEqual(repeated["leading_gap_ms"], 250)
        self.assertEqual(repeated["trailing_gap_ms"], 3_750)
        gap = repeated["max_sample_gap"]
        self.assertEqual(gap["duration_ms"], 3_000)
        self.assert_utc(gap["start"], "00:00:00.250")
        self.assert_utc(gap["end"], "00:00:03.250")
        self.assertNotIn("gap_exceeded", repeated)

    def test_gate_checks_leading_inter_sample_and_trailing_gaps(self):
        inputs = matrix(
            metric("leading", 5, 7.5, 10),
            metric("interior", 0, 4, 9, 10),
            metric("trailing", 0, 2.5, 5),
            metric("within", 0, 4, 8, 10),
        )

        report = self.assert_json(self.inspect(inputs, max_gap="4s"), 1)

        self.assertEqual(report["gate"], {"max_gap_ms": 4_000, "passed": False})
        series = {item["series"]: item for item in report["series"]}
        self.assertEqual(series["leading"]["leading_gap_ms"], 5_000)
        self.assertEqual(series["interior"]["max_sample_gap"]["duration_ms"], 5_000)
        self.assertEqual(series["trailing"]["trailing_gap_ms"], 5_000)
        self.assertEqual({name: item["gap_exceeded"] for name, item in series.items()}, {
            "leading": True, "interior": True, "trailing": True, "within": False,
        })

    def test_gate_accepts_gaps_equal_to_threshold_including_single_sample(self):
        inputs = matrix(metric("single", 5), metric("adjacent", 0, 5, 10))

        report = self.assert_json(self.inspect(inputs, max_gap="5s"), 0)

        self.assertEqual(report["gate"], {"max_gap_ms": 5_000, "passed": True})
        adjacent, single = report["series"]
        self.assertEqual(adjacent["max_sample_gap"]["duration_ms"], 5_000)
        self.assertIs(adjacent["gap_exceeded"], False)
        self.assertEqual(single["leading_gap_ms"], 5_000)
        self.assertEqual(single["trailing_gap_ms"], 5_000)
        self.assertIsNone(single["max_sample_gap"])
        self.assertIs(single["gap_exceeded"], False)

    def test_empty_capture_is_valid_and_fails_only_an_enabled_gate(self):
        standalone = self.assert_json(self.inspect(matrix()), 0)
        gated = self.assert_json(self.inspect(matrix(), max_gap="10s"), 1)

        self.assertIsNone(standalone["gate"])
        self.assertEqual(gated["gate"], {"max_gap_ms": 10_000, "passed": False})
        for report in (standalone, gated):
            self.assertEqual(report["series_count"], 0)
            self.assertEqual(report["sample_count"], 0)
            self.assertEqual(report["series"], [])

    def test_markdown_output_is_rendered_for_a_valid_capture(self):
        inputs = matrix(metric("payment_requests_total", 0, 10))
        result = self.inspect(inputs, output_format="markdown")
        default = self.inspect(inputs, output_format=None)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(default.returncode, 0, f"{default.stdout}\n{default.stderr}")
        self.assertEqual(default.stdout, result.stdout)
        self.assertRegex(result.stdout, r"(?m)^#+ ")
        self.assertIn("payment_requests_total", unescape(result.stdout))

    def test_operational_errors_do_not_print_a_report(self):
        good = matrix(metric("n_total", 0))
        warning = {**good, "warnings": ["backend returned partial data"]}
        malformed = matrix({"metric": {"__name__": "n_total"}, "values": ["12"]})
        conditions = (
            ((good, warning), None, r"(?i)warning|capture"),
            ((good, malformed), None, r"(?i)sample|pair"),
            ((good,), "0ms", r"(?i)positive|max-gap"),
        )
        for responses, max_gap, diagnostic in conditions:
            with self.subTest(diagnostic=diagnostic):
                result = self.inspect(*responses, max_gap=max_gap)

                self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
                self.assertEqual(result.stdout, "")
                self.assertRegex(result.stderr, diagnostic)


if __name__ == "__main__":
    unittest.main()
