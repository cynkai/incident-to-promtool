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
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
AFTER = DEMO / "after.rules.yml"


class CompareBundleBatchIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(executable).resolve() if executable else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.first = cls.create_bundle("z late incident/capture.zip", DEMO / "demo.json", DEMO / "before.rules.yml")

        config = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        early_check = {**config["expectations"][1], "at": "0s"}
        config["expectations"] = [early_check]
        early_config = cls.workspace / "early incident.json"
        early_config.write_text(json.dumps(config), encoding="utf-8")
        alert, = early_check["alerts"]
        early_rule = cls.workspace / "early.rules.yml"
        early_rule.write_text(json.dumps({
            "groups": [{"name": "payment", "rules": [{
                "alert": early_check["alertname"], "expr": "vector(1)", **alert,
            }]}],
        }), encoding="utf-8")
        additional = cls.workspace / "additional.rules.yml"
        additional.write_text(
            "groups:\n- name: extra\n  rules:\n  - record: extra_total\n    expr: vector(1)\n", encoding="utf-8",
        )
        cls.second = cls.create_bundle("a early incident/capture.zip", early_config, early_rule, additional)

    @classmethod
    def create_bundle(cls, name, config, *rules):
        archive = cls.workspace / name
        archive.parent.mkdir(parents=True, exist_ok=True)
        command = [sys.executable, CLI, "bundle", config, "--matrix", DEMO / "incident.matrix.json", "--output", archive]
        for rule in rules:
            command.extend(("--rule-file", rule))
        result = subprocess.run(command, cwd=cls.workspace, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(f"Could not create bundle {name}:\n{result.stdout}{result.stderr}")
        return archive

    def relative(self, archive):
        return archive.relative_to(self.workspace).as_posix()

    def compare(self, name, *arguments, gate=None, promtool=None):
        if promtool is None and self.promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        report = self.workspace / f"{name}.report.json"
        command = [sys.executable, CLI, "compare-bundle", *arguments, "--after", AFTER,
                   "--promtool", promtool or self.promtool, "--json-report", report]
        if gate is not None:
            command.extend(("--gate", gate))
        result = subprocess.run(command, cwd=self.workspace, capture_output=True, text=True, timeout=30)
        return result, report

    def assert_error_with_no_report(self, result, report, diagnostic):
        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertRegex(result.stderr, diagnostic)
        self.assertEqual(result.stdout, "")
        self.assertFalse(report.exists())

    def assert_preflight_error(self, name, diagnostic, *arguments):
        marker = self.workspace / f"{name}.ran-promtool"
        executable = self.workspace / f"{name}.promtool"
        executable.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        executable.chmod(0o700)

        result, report = self.compare(name, *arguments, promtool=executable)

        self.assert_error_with_no_report(result, report, diagnostic)
        self.assertFalse(marker.exists(), "all archives must pass preflight before starting promtool")

    def assert_fixture_provenance(self, reported, archive):
        path = self.relative(archive)
        self.assertEqual(reported["path"], f"{path}!incident.test.yml")
        self.assertEqual(reported["capture_summary"], f"{path}!capture.json")
        with ZipFile(archive) as bundle:
            self.assertEqual(reported["sha256"], hashlib.sha256(bundle.read("incident.test.yml")).hexdigest())

    def test_each_bundle_uses_its_baseline_and_equal_total_still_regresses(self):
        first_path, second_path = self.relative(self.first), self.relative(self.second)

        result, report_path = self.compare("batch", first_path, second_path, gate="regressions")

        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertIn("Gate `regressions`: **Failed**", result.stdout)
        for version in ("Before", "After"):
            self.assertIn(f"| {version} | Failed | 2/3 |", result.stdout)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 1)
        self.assertNotIn("bundle", report)
        self.assertEqual(report["bundles"], [
            {"path": first_path, "rule_files": ["rules/rules-1.yml"]},
            {"path": second_path, "rule_files": ["rules/rules-1.yml", "rules/rules-2.yml"]},
        ])
        self.assertEqual(report["gate"], {"mode": "regressions", "passed": False})
        self.assertEqual(report["summary"], {
            "before": {"matched": 2, "total": 3}, "after": {"matched": 2, "total": 3},
            "newly_failed": 1, "fixed": 1, "still_failing": 0,
        })
        first, second = report["fixtures"]
        self.assert_fixture_provenance(first, self.first)
        self.assert_fixture_provenance(second, self.second)
        self.assertEqual(first["before"], {"matched": 1, "total": 2})
        self.assertEqual(first["after"], {"matched": 2, "total": 2})
        self.assertEqual(second["before"], {"matched": 1, "total": 1})
        self.assertEqual(second["after"], {"matched": 0, "total": 1})
        fixed, = first["changes"]
        failed, = second["changes"]
        self.assertEqual((fixed["alertname"], fixed["offset_ms"], fixed["change"]),
                         ("PaymentErrorsHigh", 420_000, "fixed"))
        self.assertEqual((failed["alertname"], failed["offset_ms"], failed["change"]),
                         ("PaymentErrorsHigh", 0, "newly_failed"))

    def test_single_bundle_keeps_the_existing_report_metadata(self):
        path = self.relative(self.first)

        result, report_path = self.compare("single", path)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["bundle"], {"path": path, "rule_files": ["rules/rules-1.yml"]})
        self.assertNotIn("bundles", report)
        self.assert_fixture_provenance(report["fixtures"][0], self.first)

    def test_late_invalid_archive_is_rejected_before_any_replay(self):
        invalid = self.workspace / "not a bundle.zip"
        invalid.write_bytes(b"not ZIP data\n")

        self.assert_preflight_error("invalid-late", r"(?i)not a bundle\.zip.*(?:zip|archive)",
                                    self.relative(self.first), invalid.name)

    def test_duplicate_bundle_arguments_reject_exact_and_local_aliases(self):
        alias = self.workspace / "alternate archive name.zip"
        alias.symlink_to(self.first)
        first = self.relative(self.first)
        for name, duplicate in (("exact", first), ("absolute", self.first), ("symlink", alias.name)):
            with self.subTest(name=name):
                self.assert_preflight_error(f"duplicate-{name}", r"(?i)duplicate|only once|more than once", first, duplicate)

    def test_late_native_rule_evaluation_error_produces_no_partial_report(self):
        invalid = self.workspace / "broken source.rules.yml"
        invalid.write_text("groups: [\n", encoding="utf-8")
        archive = self.create_bundle("native-error.zip", DEMO / "demo.json", invalid)

        result, report = self.compare("native-error", self.relative(self.first), archive.name)

        self.assert_error_with_no_report(result, report, r"(?i)rule|yaml|test")


if __name__ == "__main__":
    unittest.main()
