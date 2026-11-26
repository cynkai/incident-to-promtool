import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
from zipfile import BadZipFile, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
AFTER = DEMO / "after.rules.yml"
RULE_NAMES = ["rules/rules-1.yml", "rules/rules-2.yml"]
HAS_YAML = importlib.util.find_spec("yaml") is not None


class CompareBundleIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(executable).resolve() if executable else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        source = cls.workspace / "source capture"
        source.mkdir()
        before = source / "before.rules.yml"
        shutil.copyfile(DEMO / "before.rules.yml", before)
        cls.auxiliary = cls.workspace / "auxiliary.rules.yml"
        cls.auxiliary.write_text(
            "groups:\n- name: auxiliary\n  rules:\n  - alert: AuxiliaryReady\n    expr: vector(1)\n", encoding="utf-8",
        )
        shutil.copyfile(cls.auxiliary, source / cls.auxiliary.name)
        config = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        config["rule_files"] = [before.name, cls.auxiliary.name]
        config["expectations"].append({"at": "90s", "alertname": "AuxiliaryReady", "alerts": [{"labels": {}}]})
        config_path = source / "source incident.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        matrix = source / "source matrix.json"
        shutil.copyfile(DEMO / "incident.matrix.json", matrix)
        archive = source / "generated.zip"
        result = subprocess.run(
            [sys.executable, CLI, "bundle", config_path, "--matrix", matrix, "--output", archive],
            cwd=cls.workspace, capture_output=True, text=True, timeout=30,
        )
        if result.returncode:
            raise AssertionError(f"Could not generate a v1 bundle:\n{result.stdout}{result.stderr}")
        cls.archive = cls.workspace / "moved archives" / "payment capture.zip"
        cls.archive.parent.mkdir()
        archive.rename(cls.archive)
        shutil.rmtree(source)
        with ZipFile(cls.archive) as bundle:
            cls.fixture_sha = hashlib.sha256(bundle.read("incident.test.yml")).hexdigest()

    def compare(self, name, archive=None, *, after=None, gate=None, rule_format=None, promtool=None):
        if promtool is None and self.promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        archive = self.archive if archive is None else archive
        report = self.workspace / f"{name}.report.json"
        command = [
            sys.executable, CLI, "compare-bundle", archive.relative_to(self.workspace),
            "--promtool", promtool or self.promtool, "--json-report", report,
        ]
        for rule in (AFTER, self.auxiliary) if after is None else after:
            command.extend(("--after", rule))
        if gate is not None:
            command.extend(("--gate", gate))
        if rule_format is not None:
            command.extend(("--rule-format", rule_format))
        result = subprocess.run(command, cwd=self.workspace, capture_output=True, text=True, timeout=30)
        return result, report

    def copy_archive(self, filename, *, replacements=None, remove=(), additions=()):
        destination = self.workspace / filename
        replacements = replacements or {}
        with ZipFile(self.archive) as original, ZipFile(destination, "w") as modified:
            for entry in original.infolist():
                if entry.filename not in remove:
                    content = replacements[entry.filename] if entry.filename in replacements else original.read(entry)
                    modified.writestr(entry.filename, content)
            for name, content in additions:
                modified.writestr(name, content)
        return destination

    def assert_preflight_error(self, name, archive, diagnostic):
        marker = self.workspace / f"{name}.ran-promtool"
        executable = self.workspace / f"{name}.promtool"
        executable.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        executable.chmod(0o700)

        result, report = self.compare(name, archive, promtool=executable)

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertRegex(result.stderr, diagnostic)
        self.assertEqual(result.stdout, "")
        self.assertFalse(report.exists())
        self.assertFalse(marker.exists(), "invalid bundles should be rejected before starting promtool")

    def test_moved_bundle_replays_archived_baseline_and_reports_provenance(self):
        existing = set(self.workspace.rglob("*"))

        result, report_path = self.compare("fixed")

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(set(self.workspace.rglob("*")) - existing, {report_path})
        self.assertIn("| Before | Failed | 2/3 |", result.stdout)
        self.assertIn("| After | Passed | 3/3 |", result.stdout)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        archive_path = self.archive.relative_to(self.workspace).as_posix()
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["bundle"], {"path": archive_path, "rule_files": RULE_NAMES})
        self.assertEqual(report["gate"], {"mode": "strict", "passed": True})
        self.assertEqual(report["summary"]["fixed"], 1)
        fixture, = report["fixtures"]
        self.assertEqual(fixture["path"], f"{archive_path}!incident.test.yml")
        self.assertEqual(fixture["capture_summary"], f"{archive_path}!capture.json")
        self.assertEqual(fixture["sha256"], self.fixture_sha)

    def test_equal_match_count_can_still_be_a_regression(self):
        regressed_rule = self.workspace / "regressed.rules.yml"
        regressed_rule.write_text(
            self.auxiliary.read_text(encoding="utf-8").replace("vector(1)", "vector(0) > 1"), encoding="utf-8",
        )

        result, report_path = self.compare("regression", after=(AFTER, regressed_rule), gate="regressions")

        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertIn("Gate `regressions`: **Failed**", result.stdout)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["gate"], {"mode": "regressions", "passed": False})
        self.assertEqual(report["summary"], {
            "before": {"matched": 2, "total": 3}, "after": {"matched": 2, "total": 3},
            "newly_failed": 1, "fixed": 1, "still_failing": 0,
        })
        self.assertEqual({(item["alertname"], item["change"]) for item in report["fixtures"][0]["changes"]}, {
            ("PaymentErrorsHigh", "fixed"), ("AuxiliaryReady", "newly_failed"),
        })

    @unittest.skipUnless(HAS_YAML, "PyYAML unavailable")
    def test_kubernetes_format_changes_candidate_only(self):
        auxiliary = self.workspace / "auxiliary.manifest.json"
        auxiliary.write_text(json.dumps({
            "apiVersion": "monitoring.coreos.com/v1", "kind": "PrometheusRule", "metadata": {"name": "auxiliary"},
            "spec": {"groups": [{"name": "auxiliary", "rules": [{"alert": "AuxiliaryReady", "expr": "vector(1)"}]}]},
        }), encoding="utf-8")

        result, report_path = self.compare(
            "kubernetes", after=(DEMO / "kubernetes" / "after.yml", auxiliary), rule_format="kubernetes",
        )

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["before"], {"matched": 2, "total": 3})
        self.assertEqual(report["summary"]["after"], {"matched": 3, "total": 3})

    def test_non_replay_members_are_not_read(self):
        markers = {"incident.matrix.json": b"corrupt-matrix-sentinel-0", "coverage.json": b"corrupt-coverage-sentinel-0"}
        archive = self.copy_archive("unreadable-extras.zip", replacements=markers)
        data = archive.read_bytes()
        # ZIP_STORED keeps bytes uncompressed so each payload can be changed without updating its CRC.
        for marker in markers.values():
            self.assertEqual(data.count(marker), 1)
            data = data.replace(marker, marker[:-1] + b"1", 1)
        archive.write_bytes(data)
        with ZipFile(archive) as bundle:
            for name in markers:
                with self.assertRaises(BadZipFile):
                    bundle.read(name)

        result, _ = self.compare("ignored-extras", archive)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertIn("| After | Passed | 3/3 |", result.stdout)

    def test_changed_fixture_bytes_fail_sha_verification_before_promtool(self):
        with ZipFile(self.archive) as original:
            fixture = original.read("incident.test.yml")
        archive = self.copy_archive("tampered.zip", replacements={"incident.test.yml": fixture + b"\n"})

        self.assert_preflight_error("sha", archive, r"(?i)sha-?256|digest|checksum")

    def test_missing_optional_member_changes_manifest_inventory_before_promtool(self):
        archive = self.copy_archive("missing-coverage.zip", remove=("coverage.json",))

        self.assert_preflight_error("missing-coverage", archive, r"(?i)coverage\.json|inventory")

    def test_duplicate_member_is_ambiguous_before_promtool(self):
        for index, name in enumerate(("incident.test.yml", "rules/rules-1.yml")):
            with self.subTest(name=name):
                with ZipFile(self.archive) as original, warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive = self.copy_archive(f"duplicate-{index}.zip", additions=((name, original.read(name)),))

                self.assert_preflight_error(f"duplicate-{index}", archive, r"(?i)duplicate|ambiguous|more than once")

    def test_missing_referenced_baseline_rule_is_rejected_before_promtool(self):
        archive = self.copy_archive("missing-rule.zip", remove=("rules/rules-2.yml",))

        self.assert_preflight_error("missing-rule", archive, r"(?i)missing|not found|rules/rules-2\.yml")

    def test_non_zip_input_is_rejected_before_promtool(self):
        archive = self.workspace / "malformed.zip"
        archive.write_bytes(b"not a ZIP archive")

        self.assert_preflight_error("not-zip", archive, r"(?i)zip|archive")

    def test_referenced_symlink_member_is_rejected_before_promtool(self):
        member = ZipInfo("rules/rules-2.yml")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive = self.copy_archive(
            "symlink.zip", remove=(member.filename,), additions=((member, b"rules-1.yml"),),
        )

        self.assert_preflight_error("symlink", archive, r"(?i)regular|symlink|rules/rules-2\.yml")

    def test_traversal_rule_path_is_rejected_even_with_matching_fixture_hash(self):
        with ZipFile(self.archive) as original:
            fixture = json.loads(original.read("incident.test.yml"))
            capture = json.loads(original.read("capture.json"))
            rule = original.read("rules/rules-1.yml")
        fixture["rule_files"][0] = "../outside.rules.yml"
        content = (json.dumps(fixture) + "\n").encode()
        capture["fixture_sha256"] = hashlib.sha256(content).hexdigest()
        del capture["bundle_manifest_version"]
        archive = self.copy_archive(
            "traversal.zip", replacements={"incident.test.yml": content, "capture.json": json.dumps(capture)},
            remove=("manifest.json",), additions=(("../outside.rules.yml", rule),),
        )

        self.assert_preflight_error("traversal", archive, r"(?i)rule_files.*path|unsafe.*path")
        self.assertFalse((self.workspace / "outside.rules.yml").exists())


if __name__ == "__main__":
    unittest.main()
