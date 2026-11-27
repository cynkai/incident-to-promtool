import hashlib
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
SLOW = DEMO / "before.rules.yml"
FAST = DEMO / "after.rules.yml"
ALERT = "PaymentErrorsHigh"
FILENAME = "counter & <payments>.test.yml"


class CompareTimelineIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(executable).resolve() if executable else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.original = Path("original") / FILENAME
        cls.later = Path("later") / FILENAME
        cls.decoy = Path("decoy") / FILENAME
        cls.capture_summary = Path("later capture.json")
        for path in (cls.original, cls.later, cls.decoy):
            (cls.workspace / path).parent.mkdir()

        config_path = cls.workspace / "incident.json"
        config = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        for fixture, checkpoint in ((cls.original, "7m"), (cls.later, "10m")):
            config["expectations"][-1]["at"] = checkpoint
            config_path.write_text(json.dumps(config), encoding="utf-8")
            generated = cls.cli(
                config_path, "--matrix", DEMO / "incident.matrix.json", "--rule-file", FAST,
                "--output", fixture, "--summary-format", "json",
            )
            if generated.returncode:
                raise AssertionError(f"Could not generate {fixture}:\n{generated.stdout}{generated.stderr}")
            if fixture == cls.later:
                (cls.workspace / cls.capture_summary).write_text(generated.stdout, encoding="utf-8")

        data = json.loads((cls.workspace / cls.later).read_text(encoding="utf-8"))
        data["tests"][0]["alert_rule_test"] = [{"alertname": "AnotherAlert", "eval_time": "90s", "exp_alerts": []}]
        (cls.workspace / cls.decoy).write_text(json.dumps(data), encoding="utf-8")

    @classmethod
    def cli(cls, *arguments):
        return subprocess.run(
            [sys.executable, CLI, *arguments], cwd=cls.workspace, capture_output=True, text=True, timeout=30,
        )

    def require_promtool(self):
        if self.promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        return self.promtool

    def timing(self, limit="1m", *, alert=ALERT, end="10m"):
        return ("--timeline-alertname", alert, "--timeline-end", end, "--timeline-max-delay", limit)

    def compare(self, name, fixtures, *options, before=FAST, after=SLOW, promtool=None):
        machine = self.workspace / f"{name}.json"
        junit = self.workspace / f"{name}.xml"
        result = self.cli(
            "compare", *fixtures, "--before", before, "--after", after,
            "--promtool", promtool or self.require_promtool(), "--json-report", machine, "--junit-report", junit,
            *options,
        )
        return result, machine, junit

    def assert_counts(self, node, tests, failures):
        self.assertEqual({key: node.get(key) for key in ("tests", "failures", "errors", "skipped")}, {
            "tests": str(tests), "failures": str(failures), "errors": "0", "skipped": "0",
        })

    def assert_gate_reports(self, result, machine, junit, fixture, checkpoint_passed, timing_passed):
        self.assertEqual(result.returncode, int(not (checkpoint_passed and timing_passed)),
                         f"{result.stdout}\n{result.stderr}")
        self.assertIn("## Prometheus alert comparison", result.stdout)
        self.assertIn("## Prometheus alert firing timeline", result.stdout)
        report = json.loads(machine.read_text(encoding="utf-8"))
        self.assertEqual(report["gate"], {"mode": "strict", "passed": checkpoint_passed})
        self.assertEqual(report["timeline"]["fixture_path"], fixture.as_posix())
        self.assertEqual(report["timeline"]["gate"]["passed"], timing_passed)

        root = ElementTree.parse(junit).getroot()
        self.assertEqual(root.tag, "testsuites")
        self.assert_counts(root, 3, int(not checkpoint_passed) + int(not timing_passed))
        checkpoint_suite, timing_suite = root.findall("testsuite")
        self.assertEqual(checkpoint_suite.get("name"), fixture.as_posix())
        self.assert_counts(checkpoint_suite, 2, int(not checkpoint_passed))
        self.assertEqual(timing_suite.get("name"), "Alert firing delay")
        self.assert_counts(timing_suite, 1, int(not timing_passed))
        case, = timing_suite.findall("testcase")
        self.assertIn(ALERT, case.get("name", ""))
        self.assertEqual(case.get("classname"), fixture.as_posix())
        if timing_passed:
            self.assertIsNone(case.find("failure"))
        else:
            failure = case.find("failure")
            self.assertIsNotNone(failure)
            self.assertEqual(failure.get("type"), "max-delay")
            self.assertEqual(json.loads(failure.text), report["timeline"]["gate"])
        return report

    def test_checkpoint_and_first_firing_gates_fail_independently(self):
        cases = (
            ("both pass", self.original, SLOW, FAST, "0s", True, True, 1, 2),
            ("timing only", self.later, FAST, SLOW, "1m", True, False, 2, 2),
            ("checkpoint only", self.original, FAST, SLOW, "240s", False, True, 2, 1),
            ("both fail", self.original, FAST, SLOW, "1m", False, False, 2, 1),
        )
        for name, fixture, before, after, delay, checkpoint_passed, timing_passed, matched_before, matched_after in cases:
            with self.subTest(case=name):
                original = (self.workspace / fixture).read_bytes()
                result, machine, junit = self.compare(name, (fixture,), *self.timing(delay), before=before, after=after)

                report = self.assert_gate_reports(result, machine, junit, fixture, checkpoint_passed, timing_passed)
                self.assertEqual(report["summary"]["before"], {"matched": matched_before, "total": 2})
                self.assertEqual(report["summary"]["after"], {"matched": matched_after, "total": 2})
                timeline_group, = report["timeline"]["groups"]
                self.assertEqual(timeline_group["first_firing_delta_ms"], -240_000 if after == FAST else 240_000)
                self.assertEqual((self.workspace / fixture).read_bytes(), original)

    def test_combined_timeline_matches_standalone_including_verified_capture(self):
        result, machine, junit = self.compare(
            "verified", (self.later,), *self.timing(), "--capture-summary", self.capture_summary,
        )
        standalone = self.cli(
            "timeline", self.later, "--before", FAST, "--after", SLOW, "--alertname", ALERT, "--end", "10m",
            "--max-delay", "1m", "--capture-summary", self.capture_summary, "--promtool", self.require_promtool(),
            "--format", "json",
        )

        report = self.assert_gate_reports(result, machine, junit, self.later, True, False)
        self.assertEqual(standalone.returncode, 1, f"{standalone.stdout}\n{standalone.stderr}")
        timeline = report["timeline"]
        self.assertEqual(timeline, json.loads(standalone.stdout))
        self.assertEqual(timeline["capture_summary"], self.capture_summary.as_posix())
        checksum = hashlib.sha256((self.workspace / self.later).read_bytes()).hexdigest()
        self.assertEqual(timeline["fixture_sha256"], checksum)

    def test_batch_selects_the_normalized_path_and_reuses_each_promtool_call(self):
        real_promtool = shlex.quote(str(self.require_promtool()))
        marker = self.workspace / "promtool argument log"
        wrapper = self.workspace / "recording promtool"
        wrapper.write_text(
            f"""#!/bin/sh
printf '%s %s %s\\n' "$1" "$2" "$#" >> {shlex.quote(str(marker))}
exec {real_promtool} "$@"
""",
            encoding="utf-8",
        )
        wrapper.chmod(0o700)

        result, machine, junit = self.compare(
            "batch", (self.decoy, self.later), *self.timing(),
            "--timeline-fixture", f"./later//{FILENAME}", promtool=wrapper,
        )

        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(marker.read_text(encoding="utf-8").splitlines(), ["test rules 6", "test rules 6"])
        report = json.loads(machine.read_text(encoding="utf-8"))
        self.assertEqual([item["path"] for item in report["fixtures"]], [self.decoy.as_posix(), self.later.as_posix()])
        self.assertEqual(report["summary"]["after"], {"matched": 3, "total": 3})
        self.assertTrue(report["gate"]["passed"])
        self.assertEqual(report["timeline"]["fixture_path"], self.later.as_posix())
        self.assertFalse(report["timeline"]["gate"]["passed"])
        self.assert_counts(ElementTree.parse(junit).getroot(), 4, 1)

    def test_invalid_timing_options_leave_no_report_and_never_start_promtool(self):
        marker = self.workspace / "preflight ran promtool"
        stub = self.workspace / "preflight promtool"
        stub.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        stub.chmod(0o700)
        single = (self.original,)
        batch = (self.original, self.later)
        cases = (
            ("incomplete", single, ("--timeline-alertname", ALERT), r"(?i)timeline.*(?:required|together|requires)"),
            ("only-selection", single, ("--timeline-fixture", self.original), r"(?i)timeline"),
            ("missing-selection", batch, self.timing(), r"(?i)timeline-fixture"),
            ("unknown-selection", batch, (*self.timing(), "--timeline-fixture", self.decoy), r"(?i)fixture"),
            ("absent-alert", single, self.timing(alert="MissingAlert"), r"(?i)checkpoint|MissingAlert"),
            ("off-grid", single, self.timing(end="1s"), r"(?i)align|tick|evaluation"),
            ("invalid-delay", single, self.timing("invalid"), r"(?i)duration|delay"),
        )
        for name, fixtures, options, diagnostic in cases:
            with self.subTest(case=name):
                result, machine, junit = self.compare(name, fixtures, *options, promtool=stub)

                self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
                self.assertEqual(result.stdout, "")
                self.assertRegex(result.stderr, diagnostic)
                for path in (marker, machine, junit):
                    self.assertFalse(path.exists(), f"failed preflight should not create {path.name}")

    def test_compare_bundle_does_not_accept_compare_timing_options(self):
        result = self.cli("compare-bundle", "archived.zip", "--after", FAST, *self.timing())

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(result.stdout, "")
        self.assertIn("unrecognized arguments", result.stderr)
        self.assertIn("--timeline-alertname", result.stderr)


if __name__ == "__main__":
    unittest.main()
