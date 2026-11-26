import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
START_SECONDS = 1_735_689_600


class BoundedIntervalIntegrationTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        self.config = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        self.config["end"] = "2025-01-01T00:33:20Z"
        self.config["sample_interval"] = "auto"

    def generate(self, name, offsets, *options):
        matrix = {
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [{
                    "metric": {"__name__": "payment_http_requests_total", "code": "500"},
                    "values": [[START_SECONDS + offset / 1000, str(index)] for index, offset in enumerate(offsets)],
                }],
            },
        }
        config = self.workspace / "incident.json"
        config.write_text(json.dumps(self.config), encoding="utf-8")
        capture = self.workspace / "matrix.json"
        capture.write_text(json.dumps(matrix), encoding="utf-8")
        fixture = self.workspace / name
        result = subprocess.run(
            [
                sys.executable, CLI, config, "--matrix", capture,
                "--rule-file", DEMO / "after.rules.yml", "--output", fixture, *options,
            ],
            cwd=self.workspace, capture_output=True, text=True, timeout=30,
        )
        return result, fixture

    def assert_fixture(self, result, path, interval, values):
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        fixture = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(fixture["evaluation_interval"], "30s")
        group, = fixture["tests"]
        self.assertEqual(group["interval"], interval)
        series, = group["input_series"]
        self.assertEqual(series["values"], values)
        self.assertEqual([test["eval_time"] for test in group["alert_rule_test"]], ["90s", "420s"])

    def assert_no_fixture(self, result, path, message):
        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertRegex(result.stderr, message)
        self.assertFalse(path.exists())

    def test_oversized_exact_grid_uses_finest_grid_only_when_enabled(self):
        # Both 2ms and 3ms stay within the window; the finer one should win.
        self.config["end"] = "2025-01-01T00:33:20.001Z"
        offsets = (0, 1, 2_000_000)

        exact, exact_path = self.generate("exact.test.yml", offsets)
        bounded, bounded_path = self.generate("bounded.test.yml", offsets, "--max-shift", "2ms")

        self.assert_no_fixture(exact, exact_path, r"2,000,000")
        self.assert_fixture(bounded, bounded_path, "2ms", "0 1 _x999998 2")

    def test_available_exact_grid_is_preferred_even_with_shift_budget(self):
        result, fixture = self.generate("exact-fits.test.yml", (0, 1, 600_000), "--max-shift", "2ms")

        self.assert_fixture(result, fixture, "1ms", "0 1 _x599998 2")

    def test_bounded_grid_rejects_samples_colliding_in_same_series(self):
        result, fixture = self.generate("collision.test.yml", (0, 1, 2, 2_000_000), "--max-shift", "2ms")

        self.assert_no_fixture(result, fixture, r"(?i)collision|bounded|--max-shift")

    def test_grid_search_skips_candidate_that_moves_sample_after_end(self):
        self.config["end"] = "2025-01-01T00:33:20.001Z"
        offsets = (0, 1, 2_000_001)

        too_small, too_small_path = self.generate("past-end.test.yml", offsets, "--max-shift", "1ms")
        valid, valid_path = self.generate("end-preserved.test.yml", offsets, "--max-shift", "2ms")

        self.assert_no_fixture(too_small, too_small_path, r"(?i)end|bounded|--max-shift")
        self.assert_fixture(valid, valid_path, "3ms", "0 1 _x666665 2")

    def test_shift_budget_requires_auto_interval(self):
        self.config["sample_interval"] = "30s"

        result, fixture = self.generate("numeric.test.yml", (0, 600_000), "--max-shift", "2ms")

        self.assert_no_fixture(result, fixture, r"(?i)--max-shift[^\n]*auto")


if __name__ == "__main__":
    unittest.main()
