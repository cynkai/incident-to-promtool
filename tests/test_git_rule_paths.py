import hashlib
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
BEFORE_PATH = "legacy rules/payment [combined].yml"
AFTER_PATHS = ("new rules/split/[auxiliary] alert.yml", "new rules/payment [main].yml")
SHARED_PATH = "shared compatibility/payment rules.yml"
FIXTURE_PATH = "fixture files/payment [captured].test.yml"
SUMMARY_PATH = "fixture files/capture [payment].json"


def auxiliary_rule(expression):
    return f"  - name: auxiliary\n    rules:\n      - alert: AuxiliaryReady\n        expr: {expression}\n"


class GitRulePathIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("git"):
            raise unittest.SkipTest("Git is required for scoped rule comparison")
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(executable).resolve() if executable else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.repo = cls.workspace / "repository with spaces"
        cls.repo.mkdir()
        cls.git("init", "--quiet")
        for relative in (BEFORE_PATH, *AFTER_PATHS, SHARED_PATH, FIXTURE_PATH):
            (cls.repo / relative).parent.mkdir(parents=True, exist_ok=True)

        original = (DEMO / "before.rules.yml").read_text(encoding="utf-8").rstrip() + "\n"
        baseline = original + auxiliary_rule("vector(0) > 1")
        (cls.repo / BEFORE_PATH).write_text(baseline, encoding="utf-8")
        (cls.repo / SHARED_PATH).write_text(baseline, encoding="utf-8")
        config = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        config["expectations"].append({"at": "90s", "alertname": "AuxiliaryReady", "alerts": [{"labels": {}}]})
        config_path = cls.workspace / "source incident.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        generated = subprocess.run(
            [
                sys.executable, CLI, config_path, "--matrix", DEMO / "incident.matrix.json",
                "--rule-file", BEFORE_PATH, "--output", FIXTURE_PATH, "--summary-format", "json",
            ],
            cwd=cls.repo, capture_output=True, text=True, timeout=30,
        )
        if generated.returncode:
            raise AssertionError(f"Could not generate historical fixture:\n{generated.stdout}{generated.stderr}")
        (cls.repo / SUMMARY_PATH).write_text(generated.stdout, encoding="utf-8")
        cls.fixture_sha = hashlib.sha256((cls.repo / FIXTURE_PATH).read_bytes()).hexdigest()
        cls.git("add", "--", ".")
        cls.git("commit", "--quiet", "-m", "Capture fixture and combined baseline rules")
        cls.before = cls.git("rev-parse", "HEAD").strip()

        (cls.repo / BEFORE_PATH).unlink()
        proposed = (DEMO / "after.rules.yml").read_text(encoding="utf-8").rstrip() + "\n"
        extra = auxiliary_rule("vector(1)")
        (cls.repo / AFTER_PATHS[0]).write_text("groups:\n" + extra, encoding="utf-8")
        (cls.repo / AFTER_PATHS[1]).write_text(proposed, encoding="utf-8")
        (cls.repo / SHARED_PATH).write_text(proposed + extra, encoding="utf-8")
        (cls.repo / FIXTURE_PATH).write_bytes(b"unusable fixture in the candidate commit\n")
        (cls.repo / SUMMARY_PATH).unlink()
        cls.git("add", "--", ".")
        cls.git("commit", "--quiet", "-m", "Split and fix the rules without replacing the capture")
        cls.after = cls.git("rev-parse", "HEAD").strip()

        (cls.repo / AFTER_PATHS[0]).write_bytes(b"groups: [unsuitable staged rules\n")
        cls.git("add", "--", AFTER_PATHS[0])
        (cls.repo / AFTER_PATHS[0]).write_bytes(b"groups: [different working rules\n")
        (cls.repo / FIXTURE_PATH).unlink()
        (cls.repo / SUMMARY_PATH).write_bytes(b"unusable untracked summary\n")

    @classmethod
    def git(cls, *arguments):
        return subprocess.run(
            [
                "git", "-C", cls.repo, "-c", "user.name=Integration Test", "-c", "user.email=test@example.invalid",
                "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", "-c", f"core.hooksPath={os.devnull}", *arguments,
            ],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout

    def scoped(self, baseline=(BEFORE_PATH,), candidate=AFTER_PATHS):
        return (*(flag for path in baseline for flag in ("--before-rule-file", path)),
                *(flag for path in candidate for flag in ("--after-rule-file", path)))

    def compare(self, name, *options, cwd=None, promtool=None, pinned=True):
        if promtool is None and self.promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        report = self.workspace / f"{name}.report.json"
        junit = self.workspace / f"{name}.report.xml"
        command = [
            sys.executable, CLI, "compare", FIXTURE_PATH, "--promtool", promtool or self.promtool,
            "--json-report", report, "--junit-report", junit, *options,
        ]
        if pinned:
            command.extend(("--fixture-ref", self.before, "--capture-summary", SUMMARY_PATH))
        result = subprocess.run(command, cwd=cwd or (self.repo / AFTER_PATHS[0]).parent,
                                capture_output=True, text=True, timeout=30)
        return result, report, junit

    def assert_preflight_error(self, name, diagnostic, *options):
        marker = self.workspace / f"{name}.ran-promtool"
        executable = self.workspace / f"{name}.promtool"
        executable.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        executable.chmod(0o700)

        result, report, junit = self.compare(name, *options, promtool=executable, pinned=False)

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertRegex(result.stderr, diagnostic)
        self.assertEqual(result.stdout, "")
        self.assertFalse(report.exists())
        self.assertFalse(junit.exists())
        self.assertFalse(marker.exists(), "invalid scoped paths should be rejected before starting promtool")

    def test_scoped_paths_replay_rename_and_split_on_the_same_pinned_fixture(self):
        def state():
            return (
                self.git("rev-parse", "HEAD"), self.git("symbolic-ref", "HEAD"), self.git("status", "--porcelain=v1"),
                self.git("diff", "--cached", "--binary"), self.git("diff", "--binary"),
            )

        original = state()
        invocations = (
            ("nested", (self.repo / AFTER_PATHS[0]).parent, ("--before-ref", "HEAD^", "--after-ref", "HEAD")),
            ("outside", self.workspace, ("--repo", self.repo, "--before-ref", self.before, "--after-ref", self.after)),
        )
        for name, cwd, refs in invocations:
            with self.subTest(cwd=name):
                result, report_path, junit = self.compare(name, *refs, *self.scoped(), cwd=cwd)

                self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
                self.assertIn("| Before | Failed | 1/3 |", result.stdout)
                self.assertIn("| After | Passed | 3/3 |", result.stdout)
                markdown = unescape(result.stdout)
                self.assertIn(f"Before rule files <code>{BEFORE_PATH}</code>.", markdown)
                proposed = ", ".join(f"<code>{path}</code>" for path in AFTER_PATHS)
                self.assertIn(f"After rule files {proposed}.", markdown)
                report = json.loads(report_path.read_text(encoding="utf-8"))
                self.assertEqual(report["commits"], {"before": self.before, "after": self.after})
                self.assertEqual(report["fixture_commit"], self.before)
                self.assertEqual(report["rule_files"], {"before": [BEFORE_PATH], "after": list(AFTER_PATHS)})
                fixture, = report["fixtures"]
                self.assertEqual(fixture["path"], FIXTURE_PATH)
                self.assertEqual(fixture["capture_summary"], SUMMARY_PATH)
                self.assertEqual(fixture["sha256"], self.fixture_sha)
                self.assertEqual({(item["alertname"], item["change"]) for item in fixture["changes"]}, {
                    ("PaymentErrorsHigh", "fixed"), ("AuxiliaryReady", "fixed"),
                })
                self.assertTrue(junit.is_file())
                self.assertEqual(state(), original)

    def test_shared_path_mode_keeps_existing_report_shape(self):
        result, report_path, _ = self.compare(
            "shared", "--before-ref", "HEAD^", "--after-ref", "HEAD", "--rule-file", SHARED_PATH,
        )

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertNotIn("rule_files", report)
        self.assertNotIn("Before rule files", result.stdout)
        self.assertEqual(report["summary"]["after"], {"matched": 3, "total": 3})

    def test_scoped_paths_require_refs_and_both_sides(self):
        refs = ("--before-ref", "HEAD^", "--after-ref", "HEAD")
        invalid = (
            ("no-before-path", (*refs, *self.scoped(baseline=()))),
            ("no-after-path", (*refs, *self.scoped(candidate=()))),
            ("no-before-ref", ("--after-ref", "HEAD", *self.scoped())),
            ("no-after-ref", ("--before-ref", "HEAD^", *self.scoped())),
        )
        for name, options in invalid:
            with self.subTest(name=name):
                self.assert_preflight_error(name, r"(?i)provide both|requires", *options)

    def test_scoped_paths_cannot_mix_with_shared_or_local_rules(self):
        refs = ("--before-ref", "HEAD^", "--after-ref", "HEAD")
        self.assert_preflight_error(
            "mixed-shared", r"(?i)choose|either|mix", *refs, *self.scoped(), "--rule-file", SHARED_PATH,
        )
        self.assert_preflight_error(
            "mixed-local", r"(?i)choose|either|mix", *self.scoped(),
            "--before", DEMO / "before.rules.yml", "--after", DEMO / "after.rules.yml",
        )

    def test_missing_rule_on_either_side_and_unsafe_paths_leave_no_reports(self):
        refs = ("--before-ref", "HEAD^", "--after-ref", "HEAD")
        invalid = (
            ("new-file-not-before", self.scoped(baseline=(AFTER_PATHS[1],)), r"(?i)not found|missing"),
            ("old-file-not-after", self.scoped(candidate=(AFTER_PATHS[1], BEFORE_PATH)), r"(?i)not found|missing"),
            ("unsafe-scoped-path", self.scoped(candidate=(f"../{AFTER_PATHS[0]}",)), r"(?i)repository root|relative|unsafe"),
        )
        for name, paths, diagnostic in invalid:
            with self.subTest(name=name):
                self.assert_preflight_error(name, diagnostic, *refs, *paths)


if __name__ == "__main__":
    unittest.main()
