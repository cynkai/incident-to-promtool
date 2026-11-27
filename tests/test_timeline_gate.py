import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
SLOW = DEMO / "before.rules.yml"
FAST = DEMO / "after.rules.yml"
ALERT = "PaymentErrorsHigh"


def gate_group(group, status, before, after):
    return {
        "group": group,
        "status": status,
        "before_first_firing_offset_ms": before,
        "after_first_firing_offset_ms": after,
        "first_firing_delta_ms": after - before if before is not None and after is not None else None,
    }


class TimelineGateIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(executable).resolve() if executable else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.fixture = "payment timing.test.yml"
        result = subprocess.run(
            [sys.executable, CLI, DEMO / "demo.json", "--matrix", DEMO / "incident.matrix.json", "--output", cls.fixture],
            cwd=cls.workspace, capture_output=True, text=True, timeout=30,
        )
        if result.returncode:
            raise AssertionError(f"Could not generate timeline fixture:\n{result.stdout}{result.stderr}")

    def timeline(self, *, fixture=None, before=SLOW, after=FAST, start=None, end="10m", max_delay=None,
                 output_format="json", promtool=None):
        if promtool is None and self.promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        command = [
            sys.executable, CLI, "timeline", fixture or self.fixture,
            "--before", before, "--after", after, "--alertname", ALERT,
            "--end", end, "--format", output_format, "--promtool", promtool or self.promtool,
        ]
        if start is not None:
            command.extend(("--start", start))
        if max_delay is not None:
            command.append(f"--max-delay={max_delay}")
        return subprocess.run(command, cwd=self.workspace, capture_output=True, text=True, timeout=30)

    def assert_gate(self, result, code, limit, checked, *groups):
        self.assertEqual(result.returncode, code, f"{result.stdout}\n{result.stderr}")
        report = json.loads(result.stdout)
        self.assertEqual(report["gate"], {
            "mode": "max-delay", "max_delay_ms": limit, "passed": code == 0,
            "checked_groups": checked, "groups": list(groups),
        })
        return report

    def test_exact_delay_limit_passes_and_one_millisecond_less_fails(self):
        ungated = self.timeline(before=FAST, after=SLOW)
        self.assertEqual(ungated.returncode, 0, f"{ungated.stdout}\n{ungated.stderr}")
        original = json.loads(ungated.stdout)
        self.assertNotIn("gate", original)

        allowed = self.timeline(before=FAST, after=SLOW, max_delay="240s")
        blocked = self.timeline(before=FAST, after=SLOW, max_delay="239999ms")

        passed = self.assert_gate(allowed, 0, 240_000, 1, gate_group(1, "passed", 330_000, 570_000))
        failed = self.assert_gate(blocked, 1, 239_999, 1, gate_group(1, "delayed", 330_000, 570_000))
        for report in (passed, failed):
            self.assertEqual({key: value for key, value in report.items() if key != "gate"}, original)

    def test_zero_limit_allows_improvements_and_unchanged_first_firing(self):
        for candidate, offset in ((FAST, 330_000), (SLOW, 570_000)):
            with self.subTest(candidate=candidate.name):
                result = self.timeline(after=candidate, max_delay="0s")

                self.assert_gate(result, 0, 0, 1, gate_group(1, "passed", 570_000, offset))

    def test_missing_candidate_firing_fails_even_with_a_lenient_delay(self):
        unrelated = self.workspace / "unrelated rule.yml"
        unrelated.write_text(json.dumps({
            "groups": [{"name": "other", "rules": [{"alert": "OtherAlert", "expr": "vector(1)"}]}],
        }), encoding="utf-8")
        cases = (
            ("alert removed", unrelated, "10m"),
            ("window ends before candidate fires", SLOW, "8m"),
        )
        for name, candidate, end in cases:
            with self.subTest(case=name):
                result = self.timeline(before=FAST, after=candidate, end=end, max_delay="10m")

                self.assert_gate(result, 1, 600_000, 1, gate_group(1, "missing_after", 330_000, None))

    def test_gate_fails_when_no_baseline_firing_can_be_observed(self):
        result = self.timeline(end="8m", max_delay="240s")

        self.assert_gate(result, 1, 240_000, 0, gate_group(1, "no_baseline", None, 330_000))

    def test_clipped_display_cannot_hide_a_delay_from_the_gate(self):
        result = self.timeline(before=FAST, after=SLOW, start="9m", max_delay="1m")

        report = self.assert_gate(result, 1, 60_000, 1, gate_group(1, "delayed", 330_000, 570_000))
        self.assertEqual(report["start_offset_ms"], 540_000)
        displayed, = report["groups"]
        self.assertEqual(displayed["before"]["first_firing_offset_ms"], 540_000)
        self.assertEqual(displayed["after"]["first_firing_offset_ms"], 570_000)
        self.assertEqual(displayed["first_firing_delta_ms"], 30_000)

    def test_mixed_groups_skip_missing_baseline_and_keep_selected_indexes(self):
        def group(case, alert):
            return {
                "interval": "30s",
                "input_series": [{"series": f'gate_signal{{scenario="{case}"}}', "values": "1 1 1"}],
                "alert_rule_test": [{"alertname": alert, "eval_time": "0s", "exp_alerts": []}],
            }

        fixture = self.workspace / "selected groups.test.yml"
        fixture.write_text(json.dumps({
            "rule_files": ["overridden.rules.yml"], "evaluation_interval": "30s",
            "tests": [group("unused", "OtherAlert"), group("covered", ALERT), group("new", ALERT)],
        }), encoding="utf-8")
        rules = {}
        for name, expression in (("baseline", 'gate_signal{scenario="covered"} > 0'), ("candidate", "gate_signal > 0")):
            path = self.workspace / f"mixed {name}.rules.yml"
            path.write_text(json.dumps({
                "groups": [{"name": "signal", "rules": [{"alert": ALERT, "expr": expression}]}],
            }), encoding="utf-8")
            rules[name] = path

        result = self.timeline(fixture=fixture.name, before=rules["baseline"], after=rules["candidate"], end="1m", max_delay="0s")

        report = self.assert_gate(result, 0, 0, 1, gate_group(2, "passed", 0, 0), gate_group(3, "no_baseline", None, 0))
        self.assertEqual([item["group"] for item in report["groups"]], [2, 3])

    def test_markdown_reports_the_failing_timing_policy(self):
        result = self.timeline(before=FAST, after=SLOW, max_delay="239s", output_format="markdown")

        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertIn("Timing gate `max-delay 239s` **Failed**", result.stdout)
        self.assertIn("Delay exceeds limit", result.stdout)

    def test_invalid_duration_or_grid_fails_before_replaying(self):
        marker = self.workspace / "timing gate preflight ran promtool"
        stub = self.workspace / "timing gate stub"
        stub.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        stub.chmod(0o700)
        for arguments, diagnostic in (
            ({"max_delay": "-1s"}, r"(?i)duration|delay"),
            ({"max_delay": "0s", "start": "1s"}, r"(?i)align|tick|evaluation"),
        ):
            with self.subTest(arguments=arguments):
                result = self.timeline(promtool=stub, **arguments)

                self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
                self.assertEqual(result.stdout, "")
                self.assertRegex(result.stderr, diagnostic)
                self.assertFalse(marker.exists(), "invalid timing gate arguments must not start promtool")


if __name__ == "__main__":
    unittest.main()
