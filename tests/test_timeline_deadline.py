import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
FAST = DEMO / "after.rules.yml"
SLOW = DEMO / "before.rules.yml"
ALERT = "PaymentErrorsHigh"


def deadline_group(group, status, first):
    return {"group": group, "status": status, "after_first_firing_offset_ms": first}


class TimelineDeadlineIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(executable).resolve() if executable else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.config = cls.workspace / "ten minute incident.json"
        cls.fixture = "late checkpoint & payments.test.yml"
        config = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        config["expectations"][-1]["at"] = "10m"
        cls.config.write_text(json.dumps(config), encoding="utf-8")
        result = cls.cli(
            cls.config, "--matrix", DEMO / "incident.matrix.json", "--rule-file", SLOW, "--output", cls.fixture,
        )
        if result.returncode:
            raise AssertionError(f"Could not generate the deadline fixture:\n{result.stdout}{result.stderr}")
        cls.unrelated = cls.workspace / "unrelated.rules.yml"
        cls.unrelated.write_text(
            "groups:\n- name: other\n  rules:\n  - alert: UnrelatedAlert\n    expr: vector(1)\n",
            encoding="utf-8",
        )

    @classmethod
    def cli(cls, *arguments):
        return subprocess.run(
            [sys.executable, CLI, *arguments], cwd=cls.workspace, capture_output=True, text=True, timeout=30,
        )

    def replay_executable(self, override):
        if override is None and self.promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        return override or self.promtool

    def timeline(self, *options, before=SLOW, after=SLOW, fixture=None, end="10m", promtool=None, format="json"):
        return self.cli(
            "timeline", fixture or self.fixture, "--before", before, "--after", after, "--alertname", ALERT,
            "--end", end, "--promtool", self.replay_executable(promtool), "--format", format, *options,
        )

    def compare(self, name, sources, *options, command="compare", promtool=None):
        machine = self.workspace / f"{name}.report.json"
        junit = self.workspace / f"{name}.report.xml"
        result = self.cli(
            command, *sources, "--promtool", self.replay_executable(promtool),
            "--json-report", machine, "--junit-report", junit, *options,
        )
        return result, machine, junit

    def write_fixture(self, name, groups):
        path = self.workspace / name
        path.write_text(json.dumps({
            "rule_files": ["replaced.rules.yml"], "evaluation_interval": "30s", "tests": groups,
        }), encoding="utf-8")
        return path

    def assert_deadline(self, report, fire_by_ms, passed, *groups):
        self.assertEqual(report["deadline_gate"], {
            "mode": "fire-by", "fire_by_ms": fire_by_ms, "passed": passed,
            "checked_groups": len(groups), "groups": list(groups),
        })

    def test_slow_unchanged_rule_passes_relative_limit_and_fails_deadline(self):
        standalone = self.timeline("--max-delay", "0s", "--fire-by", "9m")
        self.assertEqual(standalone.returncode, 1, f"{standalone.stdout}\n{standalone.stderr}")
        report = json.loads(standalone.stdout)
        self.assertTrue(report["gate"]["passed"])
        self.assertEqual(report["gate"]["groups"][0]["first_firing_delta_ms"], 0)
        self.assert_deadline(report, 540_000, False, deadline_group(1, "late", 570_000))
        self.assertFalse(report["passed"])

        outcome = self.compare(
            "combined", (self.fixture,), "--before", SLOW, "--after", SLOW,
            "--timeline-alertname", ALERT, "--timeline-end", "10m",
            "--timeline-max-delay", "0s", "--timeline-fire-by", "9m",
        )

        combined, failure = self.assert_timing_failure(outcome)
        self.assertEqual(combined["timeline"], report)
        self.assertEqual(failure.get("type"), "timing")
        self.assertEqual(json.loads(failure.text), {
            "gate": report["gate"], "deadline_gate": report["deadline_gate"], "passed": False,
        })

    def test_clipped_display_and_absent_baseline_do_not_change_deadline(self):
        for threshold, limit, passed in (("330s", 330_000, True), ("329999ms", 329_999, False)):
            with self.subTest(threshold=threshold):
                result = self.timeline("--start", "9m", "--fire-by", threshold, before=self.unrelated, after=FAST)

                self.assertEqual(result.returncode, int(not passed), f"{result.stdout}\n{result.stderr}")
                report = json.loads(result.stdout)
                self.assertNotIn("gate", report)
                self.assertEqual(report["passed"], passed)
                visible, = report["groups"]
                self.assertIsNone(visible["before"]["first_firing_offset_ms"])
                self.assertEqual(visible["after"]["first_firing_offset_ms"], 540_000)
                status = "passed" if passed else "late"
                self.assert_deadline(report, limit, passed, deadline_group(1, status, 330_000))

    def test_deadline_only_checks_original_groups_with_positive_alert_expectations(self):
        def group(values, expected, alert=ALERT):
            return {
                "interval": "30s",
                "input_series": [{"series": "deadline_signal", "values": values}],
                "alert_rule_test": [{"alertname": alert, "eval_time": "60s", "exp_alerts": expected}],
            }

        positive = [{"exp_labels": {}}]
        groups = [
            group("1 1 1", positive, alert="DifferentAlert"),
            group("0 0 1", []),
            group("1 1 1", positive),
            group("0 1 1", positive),
            group("0 0 0", positive),
        ]
        groups[2]["alert_rule_test"].append({"alertname": ALERT, "eval_time": "30s", "exp_alerts": positive})
        fixture = self.write_fixture("positive and quiet groups.test.yml", groups)
        candidate = self.workspace / "signal.rules.yml"
        candidate.write_text(
            f"groups:\n- name: signal\n  rules:\n  - alert: {ALERT}\n    expr: deadline_signal > 0\n",
            encoding="utf-8",
        )

        result = self.timeline("--fire-by", "0s", before=self.unrelated, after=candidate, fixture=fixture, end="1m")

        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        report = json.loads(result.stdout)
        self.assertEqual([group["group"] for group in report["groups"]], [2, 3, 4, 5])
        self.assertEqual(report["groups"][0]["after"]["first_firing_offset_ms"], 60_000)
        self.assert_deadline(
            report, 0, False, deadline_group(3, "passed", 0),
            deadline_group(4, "late", 30_000), deadline_group(5, "missing_after", None),
        )

    def test_compare_bundle_deadline_only_produces_a_fire_by_junit_failure(self):
        archive = "slow incident.zip"
        bundle = self.cli(
            "bundle", self.config, "--matrix", DEMO / "incident.matrix.json", "--rule-file", SLOW, "--output", archive,
        )
        self.assertEqual(bundle.returncode, 0, f"{bundle.stdout}\n{bundle.stderr}")
        outcome = self.compare(
            "bundle", (archive,), "--after", SLOW, "--timeline-alertname", ALERT, "--timeline-end", "10m",
            "--timeline-fire-by", "9m", command="compare-bundle",
        )

        report, failure = self.assert_timing_failure(outcome)
        timeline = report["timeline"]
        self.assertEqual(timeline["bundle"], report["bundle"])
        self.assertEqual(timeline["fixture_path"], f"{archive}!incident.test.yml")
        self.assertNotIn("gate", timeline)
        self.assertFalse(timeline["passed"])
        self.assert_deadline(timeline, 540_000, False, deadline_group(1, "late", 570_000))
        self.assertEqual(failure.get("type"), "fire-by")
        self.assertEqual(json.loads(failure.text), timeline["deadline_gate"])

    def assert_timing_failure(self, outcome):
        result, machine, junit = outcome
        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertRegex(result.stdout, r"(?i)fire-by")
        report = json.loads(machine.read_text(encoding="utf-8"))
        self.assertEqual(report["gate"], {"mode": "strict", "passed": True})
        self.assertEqual(report["summary"]["after"], {"matched": 2, "total": 2})
        root = ElementTree.parse(junit).getroot()
        self.assertEqual(root.get("tests"), "3")
        self.assertEqual(root.get("failures"), "1")
        timing_suite = root.findall("testsuite")[-1]
        self.assertEqual(timing_suite.get("name"), "Alert firing delay")
        case, = timing_suite.findall("testcase")
        failure = case.find("failure")
        self.assertIsNotNone(failure)
        return report, failure

    def test_policy_can_mix_relative_absolute_and_combined_checks(self):
        sources = (self.fixture, "absolute limit.test.yml", "combined limits.test.yml")
        for path in sources[1:]:
            shutil.copyfile(self.workspace / self.fixture, self.workspace / path)
        policy = self.workspace / "mixed timing checks.json"
        check_gates = ({"max_delay": "0s"}, {"fire_by": "9m"}, {"max_delay": "0s", "fire_by": "570s"})
        policy.write_text(json.dumps({
            "schema_version": 1,
            "checks": [
                {"source": source, "alertname": ALERT, "end": "10m", **gates}
                for source, gates in zip(sources, check_gates, strict=True)
            ],
        }), encoding="utf-8")
        result, machine, junit = self.compare(
            "mixed policy", sources, "--timeline-policy", policy, "--before", SLOW, "--after", SLOW,
        )

        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        report = json.loads(machine.read_text(encoding="utf-8"))
        self.assertTrue(report["gate"]["passed"])
        policy_report = report["timeline_policy"]
        self.assertFalse(policy_report["passed"])
        relative, deadline, both = policy_report["checks"]
        self.assertEqual([relative["fixture_path"], deadline["fixture_path"], both["fixture_path"]], list(sources))
        self.assertTrue(relative["gate"]["passed"])
        self.assertNotIn("deadline_gate", relative)
        self.assertNotIn("passed", relative)
        self.assertNotIn("gate", deadline)
        self.assertFalse(deadline["passed"])
        self.assert_deadline(deadline, 540_000, False, deadline_group(1, "late", 570_000))
        self.assertTrue(both["gate"]["passed"])
        self.assertTrue(both["passed"])
        self.assert_deadline(both, 570_000, True, deadline_group(1, "passed", 570_000))
        root = ElementTree.parse(junit).getroot()
        self.assertEqual(root.get("tests"), "9")
        self.assertEqual(root.get("failures"), "1")
        suite = root.findall("testsuite")[-1]
        self.assertEqual(suite.get("tests"), "3")
        failure, = suite.findall("testcase/failure")
        self.assertEqual(failure.get("type"), "fire-by")

    def test_deadline_validation_leaves_no_report_and_never_starts_promtool(self):
        marker = self.workspace / "deadline preflight ran promtool"
        stub = self.workspace / "deadline preflight promtool"
        stub.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        stub.chmod(0o700)
        quiet = self.write_fixture("quiet only.test.yml", [{
            "alert_rule_test": [
                {"alertname": ALERT, "eval_time": "0s", "exp_alerts": []},
                {"alertname": "DifferentAlert", "eval_time": "0s", "exp_alerts": [{"exp_labels": {}}]},
            ],
        }])
        for fixture, threshold, diagnostic in (
            (self.fixture, "11m", r"(?i)fire.by|deadline"),
            (quiet, "9m", r"(?i)positive|expects? .*fir"),
        ):
            with self.subTest(fixture=fixture):
                result = self.timeline("--fire-by", threshold, fixture=fixture, promtool=stub)
                self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
                self.assertEqual(result.stdout, "")
                self.assertRegex(result.stderr, diagnostic)
                self.assertFalse(marker.exists())

        policy = self.workspace / "invalid deadline policy.json"
        cases = (
            ("beyond end", self.fixture, {"fire_by": "11m"}, r"(?i)fire.by|deadline"),
            ("no positive checkpoint", quiet, {"fire_by": "9m"}, r"(?i)positive|expects? .*fir"),
            ("missing gate", self.fixture, {}, r"(?i)max.delay|fire.by"),
            ("non-duration", self.fixture, {"fire_by": 540}, r"(?i)duration|fire.by"),
        )
        for name, fixture, gates, diagnostic in cases:
            with self.subTest(case=name):
                policy.write_text(json.dumps({
                    "schema_version": 1, "checks": [{"alertname": ALERT, "end": "10m", **gates}],
                }), encoding="utf-8")
                result, machine, junit = self.compare(
                    name, (fixture,), "--timeline-policy", policy, "--before", SLOW, "--after", SLOW, promtool=stub,
                )
                self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
                self.assertEqual(result.stdout, "")
                self.assertRegex(result.stderr, diagnostic)
                for path in (marker, machine, junit):
                    self.assertFalse(path.exists(), f"failed preflight should not create {path.name}")


if __name__ == "__main__":
    unittest.main()
