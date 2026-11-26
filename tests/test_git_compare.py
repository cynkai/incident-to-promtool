import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
RULE_PATH = "rules/payment alert.yml"


class GitCompareIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        promtool = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        if promtool is None or shutil.which("git") is None:
            raise unittest.SkipTest("Git and promtool are required; set PROMTOOL to its path")
        cls.promtool = Path(promtool).resolve()
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.repo = cls.workspace / "repo"
        cls.repo.mkdir()
        cls.git("init", "--quiet")
        cls.git("config", "--local", "user.name", "Integration Test")
        cls.git("config", "--local", "user.email", "test@example.invalid")
        cls.git("config", "--local", "commit.gpgsign", "false")
        cls.git("config", "--local", "core.hooksPath", os.devnull)
        cls.rule = cls.repo / RULE_PATH
        cls.rule.parent.mkdir()

        for version in ("before", "after"):
            shutil.copyfile(DEMO / f"{version}.rules.yml", cls.rule)
            cls.git("add", "--", RULE_PATH)
            cls.git("commit", "--quiet", "-m", f"Add {version} payment rule")
        cls.before = cls.git("rev-parse", "HEAD^").strip()
        cls.after = cls.git("rev-parse", "HEAD").strip()

        # Invalid staged and unstaged YAML ensures the comparison reads Git objects.
        cls.rule.write_text("groups: [staged\n", encoding="utf-8")
        cls.git("add", "--", RULE_PATH)
        cls.rule.write_text("groups: [unstaged\n", encoding="utf-8")
        cls.untracked = cls.repo / "untracked.txt"
        cls.untracked.write_text("keep me\n", encoding="utf-8")

        cls.fixture = cls.workspace / "payment.test.yml"
        result = subprocess.run(
            [
                sys.executable, CLI, DEMO / "demo.json", "--matrix", DEMO / "incident.matrix.json",
                "--output", cls.fixture,
            ],
            cwd=cls.workspace, capture_output=True, text=True, timeout=30,
        )
        if result.returncode:
            raise AssertionError(f"Could not generate demo fixture:\n{result.stdout}{result.stderr}")

    @classmethod
    def git(cls, *arguments):
        return subprocess.run(
            ["git", "-C", cls.repo, *arguments],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout

    def compare(self, *arguments, cwd=None):
        return subprocess.run(
            [sys.executable, CLI, "compare", self.fixture, "--promtool", self.promtool, *arguments],
            cwd=cwd or self.workspace, capture_output=True, text=True, timeout=30,
        )

    def assert_report(self, result, expected_code, before_status, after_status):
        self.assertEqual(result.returncode, expected_code, f"{result.stdout}\n{result.stderr}")
        self.assertIn("## Prometheus alert comparison", result.stdout)
        self.assertRegex(result.stdout, rf"(?im)^[^\n]*\bbefore\b[^\n]*\b{before_status}\b[^\n]*$")
        self.assertRegex(result.stdout, rf"(?im)^[^\n]*\bafter\b[^\n]*\b{after_status}\b[^\n]*$")
        revisions = re.findall(r"(?<![0-9a-f])[0-9a-f]{7,64}(?![0-9a-f])", result.stdout)
        for expected in (self.before, self.after):
            self.assertTrue(any(expected.startswith(prefix) for prefix in revisions), result.stdout)

    def test_compares_committed_rules_without_touching_checkout(self):
        branch = self.git("symbolic-ref", "HEAD")
        status = self.git("status", "--porcelain=v1")
        staged = self.git("diff", "--cached", "--binary")
        unstaged = self.git("diff", "--binary")
        working_content = self.rule.read_bytes()
        untracked_content = self.untracked.read_bytes()
        fixture_content = self.fixture.read_bytes()

        result = self.compare(
            "--repo", self.repo, "--before-ref", "HEAD^", "--after-ref", "HEAD", "--rule-file", RULE_PATH,
        )

        self.assert_report(result, 0, "Failed", "Passed")
        self.assertIn("PaymentErrorsHigh", result.stdout)
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.after)
        self.assertEqual(self.git("symbolic-ref", "HEAD"), branch)
        self.assertEqual(self.git("status", "--porcelain=v1"), status)
        self.assertEqual(self.git("diff", "--cached", "--binary"), staged)
        self.assertEqual(self.git("diff", "--binary"), unstaged)
        self.assertEqual(self.rule.read_bytes(), working_content)
        self.assertEqual(self.untracked.read_bytes(), untracked_content)
        self.assertEqual(self.fixture.read_bytes(), fixture_content)

    def test_regression_resolves_repo_from_current_subdirectory(self):
        result = self.compare(
            "--before-ref", self.after, "--after-ref", self.before,
            "--rule-file", RULE_PATH, cwd=self.rule.parent,
        )

        self.assert_report(result, 1, "Passed", "Failed")

    def test_missing_rule_path_is_operational_error(self):
        result = self.compare(
            "--repo", self.repo, "--before-ref", "HEAD^", "--after-ref", "HEAD",
            "--rule-file", "rules/missing.yml",
        )

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertIn("rules/missing.yml", result.stderr)

    def test_missing_ref_is_operational_error(self):
        result = self.compare(
            "--repo", self.repo, "--before-ref", "HEAD^", "--after-ref", "no-such-revision",
            "--rule-file", RULE_PATH,
        )

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertIn("no-such-revision", result.stderr)

    def test_cannot_mix_local_rules_with_git_refs(self):
        result = self.compare(
            "--repo", self.repo, "--before-ref", "HEAD^", "--after-ref", "HEAD", "--rule-file", RULE_PATH,
            "--before", DEMO / "before.rules.yml", "--after", DEMO / "after.rules.yml",
        )

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertRegex(result.stderr, r"(?i)mix|mode|together|choose|cannot|either")

    def test_non_repository_is_operational_error(self):
        result = self.compare(
            "--repo", self.workspace, "--before-ref", "HEAD^", "--after-ref", "HEAD", "--rule-file", RULE_PATH,
        )

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertRegex(result.stderr, r"(?i)repository|git")


if __name__ == "__main__":
    unittest.main()
