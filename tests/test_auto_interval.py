import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"


class AutomaticIntervalIntegrationTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        self.config = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        self.config["sample_interval"] = "auto"
        self.matrix = json.loads((DEMO / "incident.matrix.json").read_text(encoding="utf-8"))
        self.values = self.matrix["data"]["result"][0]["values"]

    def generate(self, name, *options):
        config = self.workspace / "incident.json"
        config.write_text(json.dumps(self.config), encoding="utf-8")
        capture = self.workspace / "capture.json"
        capture.write_text(json.dumps(self.matrix), encoding="utf-8")
        fixture = self.workspace / name
        result = subprocess.run(
            [
                sys.executable, CLI, config, "--matrix", capture,
                "--rule-file", DEMO / "after.rules.yml", "--output", fixture, *options,
            ],
            cwd=self.workspace, capture_output=True, text=True, timeout=30,
        )
        return result, fixture

    def read_generated_fixture(self, result, fixture):
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        return json.loads(fixture.read_text(encoding="utf-8"))

    def test_on_grid_auto_matches_explicit_interval(self):
        auto_result, auto_path = self.generate("auto.test.yml")
        self.config["sample_interval"] = "30s"
        explicit_result, explicit_path = self.generate("explicit.test.yml")

        automatic = self.read_generated_fixture(auto_result, auto_path)
        explicit = self.read_generated_fixture(explicit_result, explicit_path)
        self.assertEqual(automatic, explicit)
        self.assertEqual(automatic["tests"][0]["interval"], "30s")

    def test_off_grid_auto_preserves_raw_timestamp_even_with_round_up_flag(self):
        self.values.insert(1, [self.values[0][0] + 5.25, "0"])
        auto_result, auto_path = self.generate("off-grid.test.yml")
        round_result, round_path = self.generate("off-grid-round-option.test.yml", "--round-up")

        automatic = self.read_generated_fixture(auto_result, auto_path)
        with_round_option = self.read_generated_fixture(round_result, round_path)
        self.assertEqual(automatic, with_round_option)
        self.assertEqual(automatic["evaluation_interval"], "30s")
        group, = automatic["tests"]
        self.assertEqual(group["interval"], "750ms")
        series, = group["input_series"]
        self.assertEqual(series["values"].split()[:5], ["0", "_x6", "0", "_x32", "0"])
        self.assertEqual([test["eval_time"] for test in group["alert_rule_test"]], ["90s", "420s"])

    @unittest.skipUnless(shutil.which(os.environ.get("PROMTOOL", "promtool")), "promtool is unavailable")
    def test_off_grid_auto_fixture_passes_with_promtool(self):
        self.values.insert(1, [self.values[0][0] + 5.25, "0"])
        generation, fixture = self.generate("promtool.test.yml")
        self.read_generated_fixture(generation, fixture)
        promtool = Path(shutil.which(os.environ.get("PROMTOOL", "promtool"))).resolve()

        result = subprocess.run(
            [promtool, "test", "rules", fixture],
            cwd=self.workspace, capture_output=True, text=True, timeout=30,
        )

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertIn("SUCCESS", result.stdout)

    def test_expanded_grid_limit_reports_actionable_error_and_no_fixture(self):
        self.config["end"] = "2025-01-01T00:33:20Z"
        start = self.values[0][0]
        self.values[:] = [[start, "0"], [start + 0.001, "0"], [start + 2_000, "1200"]]

        result, fixture = self.generate("over-limit.test.yml")

        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertIn("2,000,000", result.stderr)
        self.assertRegex(result.stderr, r"(?i)shorten|shorter|narrow|--round-up|sample_interval")
        self.assertFalse(fixture.exists())

    def test_auto_still_rejects_checkpoints_between_evaluations(self):
        self.config["expectations"][0]["at"] = "5s"

        result, fixture = self.generate("between-evaluations.test.yml")

        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertIn("evaluation ticks", result.stderr)
        self.assertFalse(fixture.exists())


if __name__ == "__main__":
    unittest.main()
