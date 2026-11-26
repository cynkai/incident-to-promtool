import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


CLI = Path(__file__).resolve().parents[1] / "incident_to_promtool.py"


class RegressionGateIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        promtool = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        if promtool is None:
            raise unittest.SkipTest("promtool unavailable; set PROMTOOL to its path")
        cls.promtool = Path(promtool).resolve()
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.before = cls.write_rules("before.rules.yml", "gate_signal > 1")
        cls.after = cls.write_rules("after.rules.yml", "gate_signal == 1")

    @classmethod
    def write_rules(cls, filename, expression):
        path = cls.workspace / filename
        path.write_text(json.dumps({
            "groups": [{
                "name": "gate",
                "rules": [
                    {"alert": "GateAlert", "expr": expression},
                    {"alert": "StableAlert", "expr": "gate_signal > 3"},
                ],
            }],
        }), encoding="utf-8")
        return path

    def write_fixture(self, filename, *groups):
        fixture = self.workspace / filename
        fixture.write_text(json.dumps({
            "rule_files": [self.after.name], "evaluation_interval": "30s", "tests": groups,
        }), encoding="utf-8")
        return fixture.name

    @staticmethod
    def group(name, samples, *checkpoints):
        return {
            "name": name,
            "interval": "30s",
            "input_series": [{"series": "gate_signal", "values": samples}],
            "alert_rule_test": [
                {"alertname": alert, "eval_time": at, "exp_alerts": [{}]}
                for alert, at in checkpoints
            ],
        }

    def compare(self, *fixtures, gate=None):
        arguments = [
            sys.executable, CLI, "compare", *fixtures,
            "--before", self.before, "--after", self.after, "--promtool", self.promtool,
        ]
        if gate is not None:
            arguments.extend(("--gate", gate))
        return subprocess.run(arguments, cwd=self.workspace, capture_output=True, text=True, timeout=30)

    def assert_gate(self, result, expected_code, mode):
        self.assertEqual(result.returncode, expected_code, f"{result.stdout}\n{result.stderr}")
        self.assertIn("## Prometheus alert comparison", result.stdout)
        outcome = "Passed" if expected_code == 0 else "Failed"
        self.assertIn(f"Gate `{mode}`: **{outcome}**", result.stdout)

    def assert_change(self, result, fixture, group, alert, offset, status):
        self.assertIn(f"| <code>{fixture}</code> | {group} | <code>{alert}</code> | {offset} | {status} |", result.stdout)

    def test_fix_and_regression_with_same_totals_fail_gate(self):
        fixture = self.write_fixture("offsets.test.yml", self.group(
            "mixed", "1 2 2", ("GateAlert", "0s"), ("GateAlert", "1m"), ("StableAlert", "60s"),
        ))

        result = self.compare(fixture, gate="regressions")

        self.assert_gate(result, 1, "regressions")
        self.assertIn("| Before | Failed | 1/3 |", result.stdout)
        self.assertIn("| After | Failed | 1/3 |", result.stdout)
        self.assert_change(result, fixture, 1, "GateAlert", "0s", "Fixed")
        self.assert_change(result, fixture, 1, "GateAlert", "60s", "Newly failed")
        self.assert_change(result, fixture, 1, "StableAlert", "60s", "Still failing")

    def test_persistent_failure_blocks_strict_only(self):
        fixture = self.write_fixture("persistent.test.yml", self.group("persistent", "0", ("GateAlert", "0s")))

        default = self.compare(fixture)
        regressions = self.compare(fixture, gate="regressions")

        self.assert_gate(default, 1, "strict")
        self.assert_gate(regressions, 0, "regressions")
        self.assertIn("| After | Failed | 0/1 |", regressions.stdout)
        self.assert_change(regressions, fixture, 1, "GateAlert", "0s", "Still failing")

    def test_fixing_baseline_failure_without_adding_one_passes(self):
        fixture = self.write_fixture("fixed.test.yml", self.group("fixed", "1", ("GateAlert", "0s")))

        result = self.compare(fixture, gate="regressions")

        self.assert_gate(result, 0, "regressions")
        self.assertIn("| Before | Failed | 0/1 |", result.stdout)
        self.assertIn("| After | Passed | 1/1 |", result.stdout)
        self.assert_change(result, fixture, 1, "GateAlert", "0s", "Fixed")

    def test_same_alert_and_time_in_different_groups_are_distinct(self):
        fixture = self.write_fixture(
            "test groups.test.yml",
            self.group("repeated name", "1", ("GateAlert", "0s")),
            self.group("repeated name", "2", ("GateAlert", "0s")),
        )

        result = self.compare(fixture, gate="regressions")

        self.assert_gate(result, 1, "regressions")
        self.assertIn("| Before | Failed | 1/2 |", result.stdout)
        self.assertIn("| After | Failed | 1/2 |", result.stdout)
        self.assert_change(result, fixture, 1, "GateAlert", "0s", "Fixed")
        self.assert_change(result, fixture, 2, "GateAlert", "0s", "Newly failed")

    def test_same_group_alert_and_time_in_different_fixtures_are_distinct(self):
        first = self.write_fixture("first.test.yml", self.group("shared", "1", ("GateAlert", "0s")))
        second = self.write_fixture("second.test.yml", self.group("shared", "2", ("GateAlert", "0s")))

        result = self.compare(first, second, gate="regressions")

        self.assert_gate(result, 1, "regressions")
        self.assert_change(result, first, 1, "GateAlert", "0s", "Fixed")
        self.assert_change(result, second, 1, "GateAlert", "0s", "Newly failed")

    def test_evaluation_error_is_operational_in_both_modes(self):
        fixture = self.write_fixture("bad samples.test.yml", self.group("bad", "invalid", ("GateAlert", "0s")))

        for mode in ("strict", "regressions"):
            with self.subTest(mode=mode):
                result = self.compare(fixture, gate=mode)

                self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
                self.assertNotIn("## Prometheus alert comparison", result.stdout)
                self.assertIn(fixture, result.stderr)


if __name__ == "__main__":
    unittest.main()
