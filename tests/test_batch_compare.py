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
BEFORE = DEMO / "before.rules.yml"
AFTER = DEMO / "after.rules.yml"


class BatchCompareIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        promtool = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        if promtool is None:
            raise unittest.SkipTest("promtool unavailable; set PROMTOOL to its path")
        cls.promtool = Path(promtool).resolve()
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        generated = cls.workspace / "generated.test.yml"
        result = subprocess.run(
            [
                sys.executable, CLI, DEMO / "demo.json",
                "--matrix", DEMO / "incident.matrix.json", "--output", generated,
            ],
            cwd=cls.workspace, capture_output=True, text=True, timeout=30,
        )
        if result.returncode:
            raise AssertionError(f"Could not generate demo fixture:\n{result.stdout}{result.stderr}")

        data = json.loads(generated.read_text(encoding="utf-8"))
        checkpoints = data["tests"][0]["alert_rule_test"]
        cls.pass_twice = cls.write_fixture("settlement", data)

        checkpoints.append({**checkpoints[-1], "eval_time": "8m"})
        cls.pass_three = cls.write_fixture("card payments", data)
        checkpoints.pop()

        checkpoints[-1]["exp_alerts"] = []
        cls.after_regression = cls.write_fixture("refunds", data)

    @classmethod
    def write_fixture(cls, subdirectory, data):
        relative = Path(subdirectory) / "payment.test.yml"
        path = cls.workspace / relative
        path.parent.mkdir()
        path.write_text(json.dumps(data), encoding="utf-8")
        return relative

    def compare(self, *fixtures):
        return subprocess.run(
            [
                sys.executable, CLI, "compare", *fixtures,
                "--before", BEFORE, "--after", AFTER, "--promtool", self.promtool,
            ],
            cwd=self.workspace, capture_output=True, text=True, timeout=30,
        )

    def test_mixed_after_results_report_all_fixtures_and_fail_batch(self):
        fixtures = (self.pass_three, self.after_regression)
        original = {path: (self.workspace / path).read_bytes() for path in fixtures}

        result = self.compare(*fixtures)

        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertIn("## Prometheus alert comparison", result.stdout)
        for path in fixtures:
            self.assertIn(path.as_posix(), result.stdout)
            self.assertEqual((self.workspace / path).read_bytes(), original[path])
        self.assertIn("| Before | Failed | 3/5 |", result.stdout)
        self.assertIn("| After | Failed | 4/5 |", result.stdout)
        self.assertIn(f"| <code>{self.pass_three.as_posix()}</code> | Failed (1/3) | Passed (3/3) |", result.stdout)
        self.assertIn(f"| <code>{self.after_regression.as_posix()}</code> | Passed (2/2) | Failed (1/2) |", result.stdout)
        self.assertIn("PaymentErrorsHigh", result.stdout)

    def test_all_proposed_results_pass(self):
        result = self.compare(self.pass_three, self.pass_twice)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertIn("## Prometheus alert comparison", result.stdout)
        self.assertIn(self.pass_three.as_posix(), result.stdout)
        self.assertIn(self.pass_twice.as_posix(), result.stdout)
        self.assertIn("| After | Passed | 5/5 |", result.stdout)

    def test_second_fixture_evaluation_error_aborts_without_partial_report(self):
        data = json.loads((self.workspace / self.pass_twice).read_text(encoding="utf-8"))
        data["tests"][0]["input_series"][0]["values"] = "invalid Prometheus series samples"
        malformed = self.write_fixture("invalid samples", data)

        result = self.compare(self.pass_three, malformed)

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertNotIn("## Prometheus alert comparison", result.stdout)
        self.assertIn(malformed.as_posix(), result.stderr)

    def test_relative_and_absolute_forms_of_same_fixture_are_duplicates(self):
        result = self.compare(self.pass_three, self.workspace / self.pass_three)

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertNotIn("## Prometheus alert comparison", result.stdout)
        self.assertRegex(result.stderr, r"(?i)only once|duplicate")


if __name__ == "__main__":
    unittest.main()
