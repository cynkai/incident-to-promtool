from html import unescape
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
ALERT = "PaymentErrorsHigh"


def firing(first, ticks, *intervals):
    return {
        "first_firing_offset_ms": first,
        "firing_ticks": ticks,
        "firing_intervals": [
            {"start_offset_ms": start, "end_offset_ms": end} for start, end in intervals
        ],
    }


class TimelineIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(executable).resolve() if executable else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.fixture = "payment & <daily>.test.yml"
        generated = subprocess.run(
            [sys.executable, CLI, DEMO / "demo.json", "--matrix", DEMO / "incident.matrix.json", "--output", cls.fixture],
            cwd=cls.workspace, capture_output=True, text=True, timeout=30,
        )
        if generated.returncode:
            raise AssertionError(f"Could not generate payment fixture:\n{generated.stdout}{generated.stderr}")

        cls.multigroup = "selected groups.test.yml"

        def group(name, values, alert, side):
            return {
                "name": name,
                "interval": "30s",
                "input_series": [{"series": f'gate_signal{{side="{side}"}}', "values": values}],
                "alert_rule_test": [{"alertname": alert, "eval_time": "0s", "exp_alerts": []}],
            }

        multigroup_data = {
            "rule_files": ["unused.fixture.rules.yml"], "evaluation_interval": "30s",
            "tests": [
                group("not requested", "1 1 1 1 1", "DifferentAlert", "one"),
                group("starts immediately", "1 0 1 1 0", ALERT, "one"),
                group("fires at isolated ticks", "0 1 0 0 1", ALERT, "two"),
            ],
        }
        (cls.workspace / cls.multigroup).write_text(json.dumps(multigroup_data), encoding="utf-8")

    def timeline(self, *, fixture=None, before=None, after=None, alert=ALERT, start=None, end="10m",
                 output_format="json", promtool=None):
        if promtool is None and self.promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        command = [
            sys.executable, CLI, "timeline", fixture or self.fixture,
            "--alertname", alert, "--end", end, "--promtool", promtool or self.promtool,
        ]
        for option, paths in (("--before", before or (DEMO / "before.rules.yml",)),
                              ("--after", after or (DEMO / "after.rules.yml",))):
            for path in paths:
                command.extend((option, path))
        if start is not None:
            command.extend(("--start", start))
        if output_format is not None:
            command.extend(("--format", output_format))
        return subprocess.run(command, cwd=self.workspace, capture_output=True, text=True, timeout=30)

    def assert_json(self, result, fixture, start, end):
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        report = json.loads(result.stdout)
        self.assertIs(type(report["schema_version"]), int)
        expected = {
            "schema_version": 1, "fixture_path": fixture, "alertname": ALERT, "evaluation_interval_ms": 30_000,
            "start_offset_ms": start, "end_offset_ms": end,
        }
        self.assertEqual({key: report[key] for key in expected}, expected)
        return report["groups"]

    def test_demo_reports_first_firing_and_exact_inclusive_interval(self):
        fixture = self.workspace / self.fixture
        original = fixture.read_bytes()
        original_stat = fixture.stat()

        groups = self.assert_json(self.timeline(), self.fixture, 0, 600_000)

        self.assertEqual(groups, [{
            "group": 1,
            "before": firing(570_000, 2, (570_000, 600_000)),
            "after": firing(330_000, 10, (330_000, 600_000)),
            "first_firing_delta_ms": -240_000,
        }])
        self.assertEqual(fixture.read_bytes(), original)
        self.assertEqual(fixture.stat().st_ino, original_stat.st_ino)
        self.assertEqual(fixture.stat().st_mtime_ns, original_stat.st_mtime_ns)

    def test_narrow_window_keeps_warmup_and_clips_reported_firing(self):
        result = self.timeline(start="9m", end="9m30s")

        groups = self.assert_json(result, self.fixture, 540_000, 570_000)
        self.assertEqual(groups, [{
            "group": 1,
            "before": firing(570_000, 1, (570_000, 570_000)),
            "after": firing(540_000, 2, (540_000, 570_000)),
            "first_firing_delta_ms": -30_000,
        }])

    def test_selected_groups_keep_original_indexes_and_fragmented_intervals(self):
        before = []
        for side in ("one", "two"):
            source = self.workspace / f"before {side}.rules.yml"
            source.write_text(json.dumps({
                "groups": [{"name": f"signals-{side}", "rules": [{
                    "alert": ALERT, "expr": f'gate_signal{{side="{side}"}} == 1',
                }]}],
            }), encoding="utf-8")
            before.append(source)
        replacement = self.workspace / "after different alert.rules.yml"
        replacement.write_text(json.dumps({
            "groups": [{"name": "other", "rules": [{"alert": "DifferentAlert", "expr": "vector(1)"}]}],
        }), encoding="utf-8")

        result = self.timeline(fixture=self.multigroup, before=before, after=(replacement,), end="2m")

        groups = self.assert_json(result, self.multigroup, 0, 120_000)
        self.assertEqual(groups, [{
            "group": 2,
            "before": firing(0, 3, (0, 0), (60_000, 90_000)),
            "after": firing(None, 0),
            "first_firing_delta_ms": None,
        }, {
            "group": 3,
            "before": firing(30_000, 2, (30_000, 30_000), (120_000, 120_000)),
            "after": firing(None, 0),
            "first_firing_delta_ms": None,
        }])

    def test_markdown_is_default_and_displays_fixture_and_alert(self):
        default = self.timeline(output_format=None)
        explicit = self.timeline(output_format="markdown")
        self.assertEqual(default.returncode, 0, f"{default.stdout}\n{default.stderr}")
        self.assertEqual(explicit.returncode, 0, f"{explicit.stdout}\n{explicit.stderr}")
        self.assertEqual(default.stdout, explicit.stdout)
        markdown = unescape(default.stdout)
        self.assertRegex(markdown, r"(?m)^## .*[Tt]imeline")
        self.assertIn(self.fixture, markdown)
        self.assertIn(ALERT, markdown)

    def test_invalid_requests_are_rejected_before_invoking_promtool(self):
        marker = self.workspace / "timeline preflight ran promtool"
        stub = self.workspace / "timeline stub"
        stub.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        stub.chmod(0o700)
        invalid = (
            ({"alert": "NoCheckpointForThisAlert"}, r"(?i)checkpoint|NoCheckpointForThisAlert"),
            ({"start": "1s"}, r"(?i)align|tick|evaluation"),
            ({"end": "31s"}, r"(?i)align|tick|evaluation"),
            ({"start": "60s", "end": "30s"}, r"(?i)start.*end|end.*start|range"),
            ({"start": "300000s", "end": "300000s"}, r"(?i)10[, _]?000|limit|too many"),
            ({"fixture": self.multigroup, "end": "150000s"}, r"(?i)10[, _]?000|limit|too many"),
        )
        for arguments, diagnostic in invalid:
            with self.subTest(arguments=arguments):
                result = self.timeline(promtool=stub, **arguments)

                self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
                self.assertEqual(result.stdout, "")
                self.assertRegex(result.stderr, diagnostic)
                self.assertFalse(marker.exists(), "invalid timeline request must not start promtool")


if __name__ == "__main__":
    unittest.main()
