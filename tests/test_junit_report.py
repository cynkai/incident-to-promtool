from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
BEFORE = DEMO / "before.rules.yml"
AFTER = DEMO / "after.rules.yml"
ALERT = "PaymentErrorsHigh"


class JUnitReportIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        if executable is None:
            raise unittest.SkipTest("promtool unavailable; set PROMTOOL to its path")
        cls.promtool = Path(executable).resolve()
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.first = 'first & <payments> "quoted".test.yml'
        result = cls.cli(
            DEMO / "demo.json", "--matrix", DEMO / "incident.matrix.json", "--output", cls.first,
        )
        if result.returncode:
            raise AssertionError(f"Could not generate a demo fixture:\n{result.stdout}{result.stderr}")
        fixture = json.loads((cls.workspace / cls.first).read_text(encoding="utf-8"))
        original, = fixture["tests"]
        regression = deepcopy(original)
        regression["alert_rule_test"][-1]["exp_alerts"] = []
        persistent = deepcopy(original)
        check = persistent["alert_rule_test"][-1]
        check["alertname"] = "AlwaysMissing"
        check["exp_alerts"][0]["exp_annotations"]["summary"] = 'Expected <warning> & "operator"'
        cls.second = "second & <alerts>.test.yml"
        (cls.workspace / cls.second).write_text(json.dumps({**fixture, "tests": [regression, persistent]}), encoding="utf-8")

    @classmethod
    def cli(cls, *arguments):
        return subprocess.run(
            [sys.executable, CLI, *arguments], cwd=cls.workspace,
            capture_output=True, text=True, timeout=30,
        )

    def compare(self, *fixtures, xml, machine, before=BEFORE, after=AFTER, gate=None):
        arguments = [
            "compare", *fixtures, "--before", before, "--after", after,
            "--promtool", self.promtool, "--json-report", machine, "--junit-report", xml,
        ]
        if gate is not None:
            arguments.extend(("--gate", gate))
        return self.cli(*arguments)

    def reports(self, name):
        return self.workspace / f"{name}.xml", self.workspace / f"{name}.json"

    def assert_counts(self, node, tag, tests, failures):
        self.assertEqual(node.tag, tag)
        self.assertEqual({key: node.get(key) for key in ("tests", "failures", "errors", "skipped")}, {
            "tests": str(tests), "failures": str(failures), "errors": "0", "skipped": "0",
        })

    def assert_suite(self, suite, fixture, tests, failures):
        self.assert_counts(suite, "testsuite", tests, failures)
        self.assertEqual(suite.get("name"), fixture)
        cases = suite.findall("testcase")
        self.assertEqual(len(cases), tests)
        for case in cases:
            self.assertEqual(case.get("classname"), fixture)
        by_name = {case.get("name"): case for case in cases}
        self.assertEqual(len(by_name), tests)
        return by_name

    def assert_report_error(self, result):
        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(result.stdout, "")

    def test_batch_junit_lists_every_checkpoint_and_respects_each_gate(self):
        for gate, failure_count in (("strict", 2), ("regressions", 1)):
            with self.subTest(gate=gate):
                xml, machine = self.reports(gate)

                result = self.compare(self.first, self.second, xml=xml, machine=machine, gate=gate)

                self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
                self.assertIn(f"Gate `{gate}`: **Failed**", result.stdout)
                report = json.loads(machine.read_text(encoding="utf-8"))
                self.assertEqual(report["gate"], {"mode": gate, "passed": False})
                self.assertEqual(report["summary"], {
                    "before": {"matched": 4, "total": 6}, "after": {"matched": 4, "total": 6},
                    "newly_failed": 1, "fixed": 1, "still_failing": 1,
                })
                root = ElementTree.parse(xml).getroot()
                self.assert_counts(root, "testsuites", 6, failure_count)
                first, second = root.findall("testsuite")
                first_cases = self.assert_suite(first, self.first, 2, 0)
                second_cases = self.assert_suite(second, self.second, 4, failure_count)
                self.assertEqual(set(first_cases), {f"{ALERT} @ 90s [group 1]", f"{ALERT} @ 420s [group 1]"})
                self.assertEqual(set(second_cases), {
                    f"{ALERT} @ 90s [group 1]", f"{ALERT} @ 420s [group 1]",
                    f"{ALERT} @ 90s [group 2]", "AlwaysMissing @ 420s [group 2]",
                })

                unchanged = first_cases[f"{ALERT} @ 90s [group 1]"]
                self.assertIsNone(unchanged.find("failure"))
                fixed = first_cases[f"{ALERT} @ 420s [group 1]"]
                self.assertIsNone(fixed.find("failure"))
                fixed_output = fixed.findtext("system-out")
                self.assertTrue(fixed_output.startswith("Fixed checkpoint."), fixed_output)
                self.assertIn(f"alertname: {ALERT}", fixed_output)

                new = second_cases[f"{ALERT} @ 420s [group 1]"].find("failure")
                self.assertEqual(new.get("type"), "newly_failed")
                self.assertIn(f"alertname: {ALERT}", new.text)
                persistent = second_cases["AlwaysMissing @ 420s [group 2]"]
                if gate == "strict":
                    failure = persistent.find("failure")
                    self.assertEqual(failure.get("type"), "still_failing")
                    diagnostic = failure.text
                else:
                    self.assertIsNone(persistent.find("failure"))
                    diagnostic = persistent.findtext("system-out")
                    self.assertTrue(diagnostic.startswith("Still failing. Allowed by the regressions gate."), diagnostic)
                self.assertIn("alertname: AlwaysMissing", diagnostic)
                self.assertIn("Expected <warning> &", diagnostic)

    def test_compare_bundle_can_emit_passing_junit_and_json_together(self):
        bundle = 'archived & <incident> "quoted".zip'
        generation = self.cli(
            "bundle", DEMO / "demo.json", "--matrix", DEMO / "incident.matrix.json",
            "--rule-file", BEFORE, "--output", bundle,
        )
        self.assertEqual(generation.returncode, 0, f"{generation.stdout}\n{generation.stderr}")
        xml, machine = self.reports("bundle")

        result = self.cli(
            "compare-bundle", bundle, "--after", AFTER,
            "--promtool", self.promtool, "--junit-report", xml, "--json-report", machine,
        )

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertIn("Gate `strict`: **Passed**", result.stdout)
        root = ElementTree.parse(xml).getroot()
        self.assert_counts(root, "testsuites", 2, 0)
        suite, = root.findall("testsuite")
        cases = self.assert_suite(suite, f"{bundle}!incident.test.yml", 2, 0)
        self.assertIn("Fixed checkpoint.", cases[f"{ALERT} @ 420s [group 1]"].findtext("system-out"))
        self.assertFalse(root.findall(".//failure"))
        report = json.loads(machine.read_text(encoding="utf-8"))
        self.assertEqual(report["bundle"]["path"], bundle)
        self.assertEqual(report["gate"], {"mode": "strict", "passed": True})

    def test_regressions_gate_tolerates_an_existing_failure_without_junit_failure(self):
        xml, machine = self.reports("tolerated")

        result = self.cli(
            "compare", self.first, "--before", BEFORE, "--after", BEFORE,
            "--gate", "regressions", "--promtool", self.promtool, "--junit-report", xml,
        )

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        root = ElementTree.parse(xml).getroot()
        self.assert_counts(root, "testsuites", 2, 0)
        suite, = root.findall("testsuite")
        tolerated = self.assert_suite(suite, self.first, 2, 0)[f"{ALERT} @ 420s [group 1]"]
        self.assertIn("Still failing. Allowed by the regressions gate.", tolerated.findtext("system-out"))
        self.assertFalse(root.findall(".//failure"))
        self.assertIn("| After | Failed | 1/2 |", result.stdout)
        self.assertFalse(machine.exists())

    def test_existing_either_report_leaves_other_destination_untouched(self):
        for existing_format in ("xml", "json"):
            with self.subTest(existing=existing_format):
                xml, machine = self.reports(f"existing-{existing_format}")
                occupied, untouched = (xml, machine) if existing_format == "xml" else (machine, xml)
                content = b"existing report must be preserved\n"
                occupied.write_bytes(content)
                inode = occupied.stat().st_ino

                result = self.compare(self.first, xml=xml, machine=machine)

                self.assert_report_error(result)
                self.assertIn(occupied.name, result.stderr)
                self.assertEqual(occupied.read_bytes(), content)
                self.assertEqual(occupied.stat().st_ino, inode)
                self.assertFalse(untouched.exists())

    def test_missing_report_parent_does_not_leave_partial_report(self):
        for unavailable_format in ("xml", "json"):
            with self.subTest(unavailable=unavailable_format):
                xml, machine = self.reports(f"write-error-{unavailable_format}")
                missing = self.workspace / "nonexistent reports" / f"target.{unavailable_format}"
                if unavailable_format == "xml":
                    xml = missing
                else:
                    machine = missing

                result = self.compare(self.first, xml=xml, machine=machine)

                self.assert_report_error(result)
                self.assertFalse(xml.exists())
                self.assertFalse(machine.exists())

    def test_aliases_for_the_same_output_are_rejected_without_a_report(self):
        directory = self.workspace / "report destinations"
        directory.mkdir()
        alias = self.workspace / "linked destination"
        alias.symlink_to(directory, target_is_directory=True)
        xml, machine = directory / "one.report", alias / "one.report"

        result = self.compare(self.first, xml=xml, machine=machine)

        self.assert_report_error(result)
        self.assertFalse(xml.exists())
        self.assertFalse(machine.exists())

    def test_invalid_rules_never_create_either_artifact(self):
        bad = self.workspace / "invalid.rules.yml"
        bad.write_text("groups: [\n", encoding="utf-8")
        xml, machine = self.reports("bad-input")

        result = self.compare(self.first, xml=xml, machine=machine, after=bad)

        self.assert_report_error(result)
        self.assertFalse(xml.exists())
        self.assertFalse(machine.exists())


if __name__ == "__main__":
    unittest.main()
