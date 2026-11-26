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
BUNDLE_PATH = "archived captures/payment [first].zip"
RULE_PATH = "rules/payment alert [candidate].yml"
BUNDLE_LINK = "archived captures/linked.zip"
RULE_LINK = "rules/linked.yml"


class CompareBundleGitIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("git"):
            raise unittest.SkipTest("Git is required for bundle ref comparison")
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(executable).resolve() if executable else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.repo = cls.workspace / "repository with spaces"
        cls.repo.mkdir()
        cls.git("init", "--quiet")
        cls.bundle = cls.repo / BUNDLE_PATH
        cls.bundle.parent.mkdir()
        cls.candidate = cls.repo / RULE_PATH
        cls.candidate.parent.mkdir()

        result = subprocess.run(
            [
                sys.executable, CLI, "bundle", DEMO / "demo.json", "--matrix", DEMO / "incident.matrix.json",
                "--rule-file", DEMO / "before.rules.yml", "--output", cls.bundle,
            ],
            cwd=cls.workspace, capture_output=True, text=True, timeout=30,
        )
        if result.returncode:
            raise AssertionError(f"Could not generate historical bundle:\n{result.stdout}{result.stderr}")
        with ZipFile(cls.bundle) as archive:
            cls.fixture_sha = hashlib.sha256(archive.read("incident.test.yml")).hexdigest()
        (cls.repo / BUNDLE_LINK).symlink_to(cls.bundle.name)
        cls.git("add", "--", BUNDLE_PATH, BUNDLE_LINK)
        cls.git("commit", "--quiet", "-m", "Archive original incident bundle")
        cls.before = cls.git("rev-parse", "HEAD").strip()

        shutil.copyfile(DEMO / "after.rules.yml", cls.candidate)
        (cls.repo / RULE_LINK).symlink_to(cls.candidate.name)
        cls.bundle.write_bytes(b"corrupted archive in candidate revision\n")
        cls.git("add", "--", BUNDLE_PATH, RULE_PATH, RULE_LINK)
        cls.git("commit", "--quiet", "-m", "Fix rule but replace the archived bundle")
        cls.after = cls.git("rev-parse", "HEAD").strip()

        # Neither the working copy nor the index can supply the two valid inputs.
        cls.candidate.write_bytes(b"groups: [staged invalid rule\n")
        cls.bundle.write_bytes(b"different staged invalid ZIP\n")
        cls.git("add", "--", BUNDLE_PATH, RULE_PATH)
        cls.candidate.write_bytes(b"groups: [working invalid rule\n")
        cls.bundle.write_bytes(b"different working invalid ZIP\n")
        (cls.repo / "local note.txt").write_text("preserve working tree\n", encoding="utf-8")

    @classmethod
    def git(cls, *arguments):
        return subprocess.run(
            [
                "git", "-C", cls.repo, "-c", "user.name=Integration Test", "-c", "user.email=test@example.invalid",
                "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", "-c", f"core.hooksPath={os.devnull}", *arguments,
            ],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout

    def git_options(self, bundle_ref="HEAD^", after_ref="HEAD", rule_path=RULE_PATH):
        return ("--bundle-ref", bundle_ref, "--after-ref", after_ref, "--rule-file", rule_path)

    def compare(self, name, *options, bundle_path=BUNDLE_PATH, cwd=None, promtool=None):
        if promtool is None and self.promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        report = self.workspace / f"{name}.report.json"
        result = subprocess.run(
            [
                sys.executable, CLI, "compare-bundle", bundle_path,
                "--promtool", promtool or self.promtool, "--json-report", report, *options,
            ],
            cwd=cwd or self.candidate.parent, capture_output=True, text=True, timeout=30,
        )
        return result, report

    def repository_state(self):
        return (
            self.git("rev-parse", "HEAD"), self.git("symbolic-ref", "HEAD"),
            self.git("status", "--porcelain=v1"), self.git("diff", "--cached", "--binary"), self.git("diff", "--binary"),
            self.bundle.read_bytes(), self.candidate.read_bytes(),
        )

    def assert_preflight_error(self, name, diagnostic, *options, bundle_path=BUNDLE_PATH):
        marker = self.workspace / f"{name}.ran-promtool"
        executable = self.workspace / f"{name}.promtool"
        executable.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        executable.chmod(0o700)

        result, report = self.compare(name, *options, bundle_path=bundle_path, promtool=executable)

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertRegex(result.stderr, diagnostic)
        self.assertEqual(result.stdout, "")
        self.assertFalse(report.exists())
        self.assertFalse(marker.exists(), "invalid Git comparison should not start promtool")

    def test_committed_bundle_and_candidate_compare_without_checkout(self):
        state = self.repository_state()
        invocations = (
            ("nested", self.candidate.parent, self.git_options()),
            ("outside", self.workspace, (*self.git_options(self.before, self.after), "--repo", self.repo)),
        )
        for name, cwd, options in invocations:
            with self.subTest(cwd=name):
                result, report_path = self.compare(name, *options, cwd=cwd)

                self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
                self.assertIn("Loaded the baseline rules and fixture from bundle", result.stdout)
                self.assertIn(f"at Git commit `{self.before}`.", result.stdout)
                self.assertIn(f"Read proposed rules from Git commit `{self.after}`.", result.stdout)
                self.assertIn("| Before | Failed | 1/2 |", result.stdout)
                self.assertIn("| After | Passed | 2/2 |", result.stdout)
                report = json.loads(report_path.read_text(encoding="utf-8"))
                self.assertEqual(report["commits"], {"before": self.before, "after": self.after})
                self.assertEqual(report["bundle"], {"path": BUNDLE_PATH, "rule_files": ["rules/rules-1.yml"]})
                self.assertEqual(report["gate"], {"mode": "strict", "passed": True})
                fixture, = report["fixtures"]
                self.assertEqual(fixture["path"], f"{BUNDLE_PATH}!incident.test.yml")
                self.assertEqual(fixture["capture_summary"], f"{BUNDLE_PATH}!capture.json")
                self.assertEqual(fixture["sha256"], self.fixture_sha)
                self.assertEqual(self.repository_state(), state)

    def test_refs_must_contain_the_actual_requested_file(self):
        self.assert_preflight_error(
            "missing-candidate", r"(?i)not found|missing", *self.git_options(after_ref="HEAD^"),
        )
        self.assert_preflight_error(
            "broken-zip", r"(?i)zip|archive", *self.git_options(bundle_ref="HEAD"),
        )
        self.assert_preflight_error(
            "unknown-ref", r"(?i)no-such-ref|cannot resolve", *self.git_options(bundle_ref="no-such-ref"),
        )

    def test_all_git_mode_options_are_required_together(self):
        settings = (("--bundle-ref", "HEAD^"), ("--after-ref", "HEAD"), ("--rule-file", RULE_PATH))
        for omitted, _ in settings:
            with self.subTest(omitted=omitted):
                arguments = tuple(arg for pair in settings if pair[0] != omitted for arg in pair)

                self.assert_preflight_error(omitted.removeprefix("--"), r"(?i)requires|required|together", *arguments)

    def test_local_after_and_git_mode_cannot_be_mixed(self):
        self.assert_preflight_error(
            "mixed", r"(?i)choose|either|mix|incompatible|cannot", *self.git_options(), "--after", DEMO / "after.rules.yml",
        )

    def test_git_paths_must_be_root_relative_without_traversal(self):
        for name, archive, rule in (
            ("absolute-bundle", self.bundle, RULE_PATH),
            ("traversal-bundle", f"../{BUNDLE_PATH}", RULE_PATH),
            ("traversal-rule", BUNDLE_PATH, f"rules/../{RULE_PATH}"),
        ):
            with self.subTest(name=name):
                self.assert_preflight_error(
                    name, r"(?i)relative|traversal|unsafe", *self.git_options(rule_path=rule), bundle_path=archive,
                )

    def test_git_files_must_be_regular_blobs(self):
        for name, archive, rule in (
            ("bundle-link", BUNDLE_LINK, RULE_PATH),
            ("rule-link", BUNDLE_PATH, RULE_LINK),
            ("rule-directory", BUNDLE_PATH, "rules"),
        ):
            with self.subTest(name=name):
                self.assert_preflight_error(
                    name, r"(?i)regular.file|non.regular|symlink", *self.git_options(rule_path=rule), bundle_path=archive,
                )


if __name__ == "__main__":
    unittest.main()
