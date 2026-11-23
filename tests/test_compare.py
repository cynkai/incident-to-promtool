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


class CompareIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        promtool = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        if promtool is None:
            raise unittest.SkipTest("promtool unavailable; set PROMTOOL to its path")
        cls.promtool = Path(promtool).resolve()
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.fixture = cls.workspace / "payment.test.yml"

        result = subprocess.run(
            [
                sys.executable, CLI, DEMO / "demo.json",
                "--matrix", DEMO / "incident.matrix.json",
                "--output", cls.fixture,
            ],
            cwd=cls.workspace,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode:
            raise AssertionError(f"Could not generate demo fixture:\n{result.stdout}{result.stderr}")

    def compare(self, before, after, fixture=None):
        arguments = [sys.executable, CLI, "compare", fixture or self.fixture, "--promtool", self.promtool]
        for option, paths in (("--before", before), ("--after", after)):
            for path in paths:
                arguments.extend((option, path))
        return subprocess.run(arguments, cwd=self.workspace, capture_output=True, text=True, timeout=30)

    def assert_report(self, result, expected_code, before_status, after_status):
        self.assertEqual(result.returncode, expected_code, f"{result.stdout}\n{result.stderr}")
        self.assertIn("## Prometheus alert comparison", result.stdout)
        self.assertRegex(result.stdout, rf"(?im)^[^\n]*\bbefore\b[^\n]*\b{before_status}\b[^\n]*$")
        self.assertRegex(result.stdout, rf"(?im)^[^\n]*\bafter\b[^\n]*\b{after_status}\b[^\n]*$")

    def test_fixed_rule_passes_and_report_preserves_fixture(self):
        original = self.fixture.read_bytes()
        original_stat = self.fixture.stat()
        result = self.compare([BEFORE], [AFTER])

        self.assert_report(result, 0, "Failed", "Passed")
        self.assertRegex(result.stdout, r"(?s)```[^\n]*\n.*PaymentErrorsHigh.*\n```")
        self.assertEqual(self.fixture.read_bytes(), original)
        self.assertEqual(self.fixture.stat().st_ino, original_stat.st_ino)
        self.assertEqual(self.fixture.stat().st_mtime_ns, original_stat.st_mtime_ns)

    def test_reintroducing_late_alert_fails_comparison(self):
        result = self.compare([AFTER], [BEFORE])

        self.assert_report(result, 1, "Passed", "Failed")
        self.assertIn("PaymentErrorsHigh", result.stdout)

    def test_malformed_rule_reports_operational_error(self):
        invalid = self.workspace / "invalid.rules.yml"
        invalid.write_text("groups: [\n", encoding="utf-8")

        result = self.compare([AFTER], [invalid])

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertRegex(result.stderr, r"(?i)rule|yaml")

    def test_rule_evaluation_error_is_not_an_assertion_failure(self):
        invalid = self.workspace / "duplicate-labels.rules.yml"
        invalid.write_text(
            "groups:\n  - name: invalid\n    rules:\n"
            "      - alert: PaymentErrorsHigh\n        expr: payment_http_requests_total\n"
            "        labels:\n          code: same\n",
            encoding="utf-8",
        )
        data = json.loads(self.fixture.read_text(encoding="utf-8"))
        samples = data["tests"][0]["input_series"]
        samples.append({**samples[0], "series": samples[0]["series"].replace('code="500"', 'code="501"')})
        multi_series = self.workspace / "multi-series.test.yml"
        multi_series.write_text(json.dumps(data), encoding="utf-8")

        result = self.compare([AFTER], [invalid], multi_series)

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertIn("same labelset", result.stderr)

    def test_empty_assertions_cannot_pass_comparison(self):
        data = json.loads(self.fixture.read_text(encoding="utf-8"))
        data["tests"][0]["alert_rule_test"] = []
        empty = self.workspace / "empty.test.yml"
        empty.write_text(json.dumps(data), encoding="utf-8")

        result = self.compare([AFTER], [AFTER], empty)

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertRegex(result.stderr, r"(?i)alert_rule_test|assertion|checkpoint|expectation")

    def test_multiple_rule_paths_are_used_on_each_side(self):
        second_rule = self.workspace / "secondary.rules.yml"
        second_rule.write_text(
            "groups:\n  - name: secondary\n    rules:\n"
            "      - alert: SecondaryAlert\n        expr: vector(1)\n",
            encoding="utf-8",
        )
        data = json.loads(self.fixture.read_text(encoding="utf-8"))
        data["tests"][0]["alert_rule_test"].append({
            "alertname": "SecondaryAlert", "eval_time": "7m", "exp_alerts": [{"exp_labels": {}}],
        })
        compound = self.workspace / "compound.test.yml"
        compound.write_text(json.dumps(data), encoding="utf-8")

        result = self.compare([BEFORE, second_rule], [second_rule, AFTER], compound)

        self.assert_report(result, 0, "Failed", "Passed")


if __name__ == "__main__":
    unittest.main()
