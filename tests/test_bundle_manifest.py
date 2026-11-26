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
import warnings
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
PAYLOADS = ["incident.json", "incident.matrix.json", "incident.test.yml", "capture.json", "coverage.json", "rules/rules-1.yml"]


class BundleManifestIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        real = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(real).resolve() if real else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.archive = cls.workspace / "fresh bundle.zip"
        result = subprocess.run(
            [
                sys.executable, CLI, "bundle", DEMO / "demo.json", "--matrix", DEMO / "incident.matrix.json",
                "--rule-file", DEMO / "before.rules.yml", "--output", cls.archive,
            ],
            cwd=cls.workspace, capture_output=True, text=True, timeout=30,
        )
        if result.returncode:
            raise AssertionError(f"Could not create bundle:\n{result.stdout}{result.stderr}")
        with ZipFile(cls.archive) as bundle:
            cls.original = {entry.filename: bundle.read(entry) for entry in bundle.infolist()}

    def cli(self, *arguments, env=None):
        return subprocess.run(
            [sys.executable, CLI, *arguments], cwd=self.workspace,
            env=env, capture_output=True, text=True, timeout=30,
        )

    def verify(self, archive, *, output_format="json", env=None):
        options = () if output_format is None else ("--format", output_format)
        return self.cli("verify-bundle", archive.name, *options, env=env)

    def compare(self, archive, name, *, executable=None):
        if executable is None and self.promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        report = self.workspace / f"{name}.report.json"
        result = self.cli(
            "compare-bundle", archive.name, "--after", DEMO / "after.rules.yml",
            "--promtool", executable or self.promtool, "--json-report", report,
        )
        return result, report

    def rewrite(self, name, *, replace=None, remove=(), add=()):
        archive = self.workspace / name
        replace = replace or {}
        with ZipFile(archive, "w") as bundle:
            for path, data in self.original.items():
                if path not in remove:
                    bundle.writestr(path, replace.get(path, data))
            for path, data in add:
                bundle.writestr(path, data)
        return archive

    def fake_promtool(self, path):
        marker = path.with_suffix(".started")
        path.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        path.chmod(0o700)
        return marker

    def assert_error(self, result, diagnostic):
        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertRegex(result.stderr, diagnostic)
        self.assertEqual(result.stdout, "")

    def assert_compare_rejected_before_promtool(self, archive, name, diagnostic):
        fake = self.workspace / f"{name}.promtool"
        marker = self.fake_promtool(fake)

        result, report = self.compare(archive, name, executable=fake)

        self.assert_error(result, diagnostic)
        self.assertFalse(report.exists())
        self.assertFalse(marker.exists(), "bundle verification should precede any promtool invocation")

    def test_fresh_bundle_has_hashes_for_all_payloads_and_verifies_without_promtool(self):
        with ZipFile(self.archive) as bundle:
            names = [entry.filename for entry in bundle.infolist() if not entry.is_dir()]
            self.assertCountEqual(names, [*PAYLOADS, "manifest.json"])
            self.assertEqual(names[-1], "manifest.json")
        manifest = json.loads(self.original["manifest.json"])
        self.assertIs(type(manifest["schema_version"]), int)
        self.assertEqual(manifest, {
            "schema_version": 1,
            "files": {name: hashlib.sha256(self.original[name]).hexdigest() for name in PAYLOADS},
        })
        capture = json.loads(self.original["capture.json"])
        self.assertIs(type(capture["bundle_manifest_version"]), int)
        self.assertEqual(capture["bundle_manifest_version"], 1)
        self.assertEqual(capture["fixture_sha256"], manifest["files"]["incident.test.yml"])

        tools = self.workspace / "tools"
        tools.mkdir()
        marker = self.fake_promtool(tools / "promtool")
        env = {**os.environ, "PATH": str(tools)}
        machine = self.verify(self.archive, env=env)
        default = self.verify(self.archive, output_format=None, env=env)
        markdown = self.verify(self.archive, output_format="markdown", env=env)

        for result in (machine, default, markdown):
            self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertFalse(marker.exists())
        self.assertEqual(json.loads(machine.stdout), {
            "schema_version": 1, "bundle_path": self.archive.name, "verified_files": sorted(PAYLOADS),
        })
        self.assertEqual(default.stdout, markdown.stdout)
        self.assertRegex(default.stdout, r"(?i)verif")

        uppercase = {name: digest.upper() for name, digest in manifest["files"].items()}
        rezipped = self.rewrite("rezipped bundle.zip", replace={
            "manifest.json": json.dumps({**manifest, "files": uppercase}),
        })
        reverified = self.verify(rezipped, env=env)
        self.assertEqual(reverified.returncode, 0, f"{reverified.stdout}\n{reverified.stderr}")
        self.assertEqual(json.loads(reverified.stdout)["verified_files"], sorted(PAYLOADS))

    def test_whole_verification_rejects_rezipped_tamper_that_compare_does_not_read(self):
        member = "incident.matrix.json"
        archive = self.rewrite("altered raw matrix.zip", replace={member: self.original[member] + b"\n"})
        with ZipFile(archive) as bundle:
            self.assertIsNone(bundle.testzip())

        self.assert_error(self.verify(archive), r"(?i)incident\.matrix\.json.*(?:sha-?256|hash|digest)|(?:sha-?256|hash|digest).*incident\.matrix\.json")
        result, _ = self.compare(archive, "untouched-replay")

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertIn("| After | Passed | 2/2 |", result.stdout)

    def test_compare_verifies_capture_summary_and_archived_baseline_before_promtool(self):
        for index, member in enumerate(("capture.json", "rules/rules-1.yml")):
            with self.subTest(member=member):
                archive = self.rewrite(f"altered used payload {index}.zip", replace={member: self.original[member] + b"\n"})

                self.assert_compare_rejected_before_promtool(archive, f"used-{index}", r"(?i)sha-?256|hash|digest")

    def test_required_manifest_cannot_be_silently_stripped_but_true_legacy_replays(self):
        stripped = self.rewrite("missing manifest.zip", remove=("manifest.json",))
        self.assert_error(self.verify(stripped), r"(?i)missing|manifest")
        self.assert_compare_rejected_before_promtool(stripped, "required-manifest", r"(?i)manifest")

        legacy_capture = json.loads(self.original["capture.json"])
        del legacy_capture["bundle_manifest_version"]
        legacy = self.rewrite(
            "legacy bundle.zip", remove=("manifest.json",), replace={"capture.json": json.dumps(legacy_capture)},
        )
        self.assert_error(self.verify(legacy), r"(?i)missing|manifest")
        result, report = self.compare(legacy, "legacy-replay")

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(json.loads(report.read_text(encoding="utf-8"))["gate"], {"mode": "strict", "passed": True})

    def test_verification_rejects_duplicate_extra_and_missing_members(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            duplicate = self.rewrite("duplicate payload.zip", add=(("coverage.json", self.original["coverage.json"]),))
        extra = self.rewrite("extra payload.zip", add=(("unlisted.txt", b"extra"),))
        missing = self.rewrite("missing payload.zip", remove=("coverage.json",))
        manifest = json.loads(self.original["manifest.json"])
        extended = self.rewrite("extra listed payload.zip", replace={"manifest.json": json.dumps({
            **manifest, "files": {**manifest["files"], "extra.txt": hashlib.sha256(b"extra").hexdigest()},
        })}, add=(("extra.txt", b"extra"),))

        invalid = (
            (duplicate, r"(?i)duplicate"),
            (extra, r"(?i)unlisted|extra|member"),
            (missing, r"(?i)missing|coverage\.json"),
            (extended, r"(?i)extra|member|payload|layout"),
        )
        for archive, diagnostic in invalid:
            with self.subTest(archive=archive.name):
                self.assert_error(self.verify(archive), diagnostic)

    def test_verification_rejects_bad_manifest_json_shape_and_hash(self):
        manifest = json.loads(self.original["manifest.json"])
        digest = manifest["files"]["coverage.json"]
        duplicate_file_keys = json.dumps(manifest["files"])[:-1] + f', "coverage.json": "{digest}"' + "}"
        corrupted = (
            (b"{unfinished manifest", r"(?i)manifest|json"),
            (json.dumps({**manifest, "schema_version": True}), r"(?i)version|schema"),
            (json.dumps({**manifest, "files": []}), r"(?i)files|manifest"),
            (json.dumps({**manifest, "files": {**manifest["files"], "coverage.json": "invalid-sha256"}}), r"(?i)sha-?256|hash|digest"),
            (json.dumps({**manifest, "files": {**manifest["files"], "coverage.json": digest[:-1]}}), r"(?i)sha-?256|hash|digest"),
            (json.dumps({**manifest, "files": {**manifest["files"], "coverage.json": None}}), r"(?i)sha-?256|hash|digest"),
            ('{"schema_version":1,"files":' + duplicate_file_keys + '}', r"(?i)duplicate"),
        )
        for index, (data, diagnostic) in enumerate(corrupted):
            with self.subTest(index=index):
                archive = self.rewrite(f"malformed manifest {index}.zip", replace={"manifest.json": data})

                self.assert_error(self.verify(archive), diagnostic)


if __name__ == "__main__":
    unittest.main()
