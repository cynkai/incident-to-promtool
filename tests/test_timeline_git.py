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
FAST = DEMO / "after.rules.yml"
SLOW = DEMO / "before.rules.yml"
FIXTURE = "incident fixtures/payment [archived].test.yml"
SUMMARY = "incident fixtures/payment [capture].json"
BAD_SUMMARY = "incident fixtures/payment [other digest].json"
SHARED = "active rules/payment [shared].yml"
LEGACY = "legacy rules/payment [fast].yml"
PROPOSED = "active rules/payment [slow].yml"
AUXILIARY = "active rules/extra & reporting.yml"


class TimelineGitIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("git"):
            raise unittest.SkipTest("Git is required for timeline ref replay")
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(executable).resolve() if executable else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.repo = cls.workspace / "timeline repo"
        cls.repo.mkdir()
        cls.git("init", "--quiet")
        for relative in (FIXTURE, SHARED, LEGACY):
            (cls.repo / relative).parent.mkdir(parents=True)

        shutil.copyfile(FAST, cls.repo / LEGACY)
        generated = subprocess.run(
            [
                sys.executable, CLI, DEMO / "demo.json", "--matrix", DEMO / "incident.matrix.json",
                "--rule-file", LEGACY, "--output", FIXTURE, "--summary-format", "json",
            ],
            cwd=cls.repo, capture_output=True, text=True, timeout=30,
        )
        if generated.returncode:
            raise AssertionError(f"Could not generate historical fixture:\n{generated.stdout}{generated.stderr}")
        (cls.repo / LEGACY).unlink()
        cls.fixture_bytes = (cls.repo / FIXTURE).read_bytes()
        cls.fixture_sha256 = hashlib.sha256(cls.fixture_bytes).hexdigest()
        cls.summary_bytes = generated.stdout.encode()
        (cls.repo / SUMMARY).write_bytes(cls.summary_bytes)
        wrong_hash = "0" * 64 if cls.fixture_sha256 != "0" * 64 else "1" * 64
        summary = {**json.loads(generated.stdout), "fixture_sha256": wrong_hash}
        (cls.repo / BAD_SUMMARY).write_text(json.dumps(summary), encoding="utf-8")
        cls.capture_commit = cls.commit("Capture the historical incident")

        for rule in (LEGACY, SHARED):
            shutil.copyfile(FAST, cls.repo / rule)
        cls.baseline_commit = cls.commit("Add the fast baseline rules")

        for rule in (PROPOSED, SHARED):
            shutil.copyfile(SLOW, cls.repo / rule)
        (cls.repo / AUXILIARY).write_text(
            "groups:\n  - name: reporting\n    rules:\n      - record: timeline_aux\n        expr: vector(1)\n",
            encoding="utf-8",
        )
        (cls.repo / LEGACY).unlink()
        (cls.repo / FIXTURE).write_bytes(b"fixture corrupted in the candidate commit\n")
        (cls.repo / SUMMARY).unlink()
        cls.proposed_commit = cls.commit("Rename and slow the rule without preserving the capture")

        (cls.repo / SHARED).write_bytes(b"groups: [invalid in the staged file\n")
        cls.git("add", "--", SHARED)
        (cls.repo / SHARED).write_bytes(b"groups: [invalid in the working file\n")
        (cls.repo / PROPOSED).unlink()
        (cls.repo / FIXTURE).unlink()
        (cls.repo / SUMMARY).write_bytes(b"not the committed capture summary\n")

    @classmethod
    def git(cls, *arguments):
        return subprocess.run(
            [
                "git", "-C", cls.repo, "-c", "user.name=Integration Test", "-c", "user.email=test@example.invalid",
                "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", "-c", f"core.hooksPath={os.devnull}",
                *arguments,
            ],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout

    @classmethod
    def commit(cls, message):
        cls.git("add", "--", ".")
        cls.git("commit", "--quiet", "-m", message)
        return cls.git("rev-parse", "HEAD").strip()

    def checkout_state(self):
        return (
            self.git("rev-parse", "HEAD"), self.git("symbolic-ref", "HEAD"), self.git("status", "--porcelain=v1"),
            self.git("diff", "--binary"), self.git("diff", "--cached", "--binary"),
        )

    def timeline(self, *options, fixture=FIXTURE, cwd=None, output_format="json", promtool=None):
        if promtool is None and self.promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        command = [
            sys.executable, CLI, "timeline", fixture, "--alertname", "PaymentErrorsHigh", "--end", "10m",
            "--format", output_format, "--promtool", promtool or self.promtool, *options,
        ]
        return subprocess.run(command, cwd=cwd or self.repo, capture_output=True, text=True, timeout=30)

    def test_scoped_git_rename_and_pinned_capture_gate_replays_clean_bytes(self):
        state = self.checkout_state()
        result = self.timeline(
            "--repo", self.repo, "--before-ref", self.baseline_commit, "--after-ref", self.proposed_commit,
            "--before-rule-file", LEGACY, "--after-rule-file", PROPOSED, "--after-rule-file", AUXILIARY,
            "--fixture-ref", self.capture_commit, "--capture-summary", SUMMARY,
            "--start", "9m", "--max-delay", "1m", cwd=self.workspace,
        )

        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        report = json.loads(result.stdout)
        self.assertEqual(report["commits"], {"before": self.baseline_commit, "after": self.proposed_commit})
        self.assertEqual(report["rule_files"], {"before": [LEGACY], "after": [PROPOSED, AUXILIARY]})
        self.assertEqual(report["fixture_path"], FIXTURE)
        self.assertEqual(report["fixture_commit"], self.capture_commit)
        self.assertEqual(report["fixture_sha256"], self.fixture_sha256)
        self.assertEqual(report["capture_summary"], SUMMARY)
        displayed, = report["groups"]
        self.assertEqual(displayed["first_firing_delta_ms"], 30_000)
        self.assertEqual(report["gate"], {
            "mode": "max-delay", "max_delay_ms": 60_000, "passed": False, "checked_groups": 1,
            "groups": [{
                "group": 1, "status": "delayed", "before_first_firing_offset_ms": 330_000,
                "after_first_firing_offset_ms": 570_000, "first_firing_delta_ms": 240_000,
            }],
        })
        self.assertEqual(self.checkout_state(), state)

    def test_shared_git_paths_resolve_from_a_nested_working_directory(self):
        options = (
            "--before-ref", "HEAD^", "--after-ref", "HEAD", "--rule-file", SHARED, "--fixture-ref", "HEAD~2",
        )
        nested = (self.repo / SHARED).parent
        result = self.timeline(*options, cwd=nested)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        report = json.loads(result.stdout)
        self.assertEqual(report["commits"], {"before": self.baseline_commit, "after": self.proposed_commit})
        self.assertEqual(report["rule_files"], {"before": [SHARED], "after": [SHARED]})
        self.assertEqual(report["fixture_commit"], self.capture_commit)
        self.assertEqual(report["fixture_sha256"], self.fixture_sha256)
        self.assertNotIn("capture_summary", report)
        group, = report["groups"]
        self.assertEqual(group["first_firing_delta_ms"], 240_000)

        markdown = self.timeline(*options, cwd=nested, output_format="markdown")

        self.assertEqual(markdown.returncode, 0, f"{markdown.stdout}\n{markdown.stderr}")
        document = unescape(markdown.stdout)
        for provenance in (self.baseline_commit, self.proposed_commit, self.capture_commit, self.fixture_sha256,
                           f"<code>{SHARED}</code>"):
            self.assertIn(provenance, document)

    def test_local_capture_can_be_verified_with_local_or_git_rules(self):
        fixture = self.workspace / "local payment.test.yml"
        summary = self.workspace / "local capture.json"
        fixture.write_bytes(self.fixture_bytes)
        summary.write_bytes(self.summary_bytes)
        modes = (
            ("local", ("--before", FAST, "--after", SLOW)),
            ("git", ("--repo", self.repo, "--before-ref", "HEAD^", "--after-ref", "HEAD", "--rule-file", SHARED)),
        )
        for mode, options in modes:
            with self.subTest(mode=mode):
                result = self.timeline(
                    *options, "--capture-summary", summary, fixture=fixture.name, cwd=self.workspace,
                )

                self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
                report = json.loads(result.stdout)
                self.assertNotIn("fixture_commit", report)
                self.assertEqual("commits" in report, mode == "git")
                self.assertEqual(report["fixture_sha256"], self.fixture_sha256)
                self.assertEqual(report["capture_summary"], str(summary))
                group, = report["groups"]
                self.assertEqual(group["first_firing_delta_ms"], 240_000)
        self.assertEqual(fixture.read_bytes(), self.fixture_bytes)

    def test_invalid_modes_or_pinned_capture_fail_before_promtool(self):
        marker = self.workspace / "timeline Git preflight ran promtool"
        stub = self.workspace / "timeline Git preflight stub"
        stub.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        stub.chmod(0o700)
        refs = ("--before-ref", "HEAD^", "--after-ref", "HEAD")
        shared = (*refs, "--rule-file", SHARED)
        local = ("--before", FAST, "--after", SLOW)
        pinned = (*shared, "--fixture-ref", "HEAD~2")
        cases = (
            ("mixed local and Git", FIXTURE, (*local, *shared), r"(?i)choose|either|mix"),
            ("mixed shared and scoped", FIXTURE, (*shared, "--before-rule-file", LEGACY), r"(?i)choose|either|mix"),
            ("incomplete scoped lists", FIXTURE, (*refs, "--before-rule-file", LEGACY), r"(?i)both|requires"),
            ("local fixture ref", FIXTURE, (*local, "--fixture-ref", "HEAD~2"), r"(?i)fixture-ref.*Git"),
            ("repeated capture summary", FIXTURE, (*pinned, "--capture-summary", SUMMARY,
                                                  "--capture-summary", SUMMARY), r"(?i)capture-summary"),
            ("unsafe pinned fixture", "../outside.test.yml", pinned, r"(?i)repository root|relative|unsafe"),
            ("wrong committed capture digest", FIXTURE, (*pinned, "--capture-summary", BAD_SUMMARY),
             r"(?i)sha-?256|digest"),
            ("unavailable committed capture summary", FIXTURE,
             (*shared, "--fixture-ref", "HEAD", "--capture-summary", SUMMARY), r"(?i)not found|missing"),
        )
        for name, fixture, options, diagnostic in cases:
            with self.subTest(case=name):
                result = self.timeline(*options, fixture=fixture, promtool=stub)

                self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
                self.assertEqual(result.stdout, "")
                self.assertRegex(result.stderr, diagnostic)
                self.assertFalse(marker.exists(), "invalid arguments or capture must not start promtool")


if __name__ == "__main__":
    unittest.main()
