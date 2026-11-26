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


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
BEFORE = DEMO / "before.rules.yml"
AFTER = DEMO / "after.rules.yml"


class FixtureProvenanceIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        promtool = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        if promtool is None:
            raise unittest.SkipTest("promtool unavailable; set PROMTOOL to its path")
        cls.promtool = Path(promtool).resolve()
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.fixtures = ("payment cases/card/payment.test.yml", "payment cases/refund/payment.test.yml")
        cls.summaries = ("capture/card.json", "capture/refund.json")
        (cls.workspace / "capture").mkdir()
        config = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        config_path = cls.workspace / "incident.json"
        for index, (fixture, summary) in enumerate(zip(cls.fixtures, cls.summaries)):
            if index:
                config["expectations"].append({"at": "30s", "alertname": "PaymentErrorsHigh", "alerts": []})
            config_path.write_text(json.dumps(config), encoding="utf-8")
            (cls.workspace / fixture).parent.mkdir(parents=True)
            result = subprocess.run(
                [
                    sys.executable, CLI, config_path, "--matrix", DEMO / "incident.matrix.json",
                    "--rule-file", AFTER, "--output", fixture, "--summary-format", "json",
                ],
                cwd=cls.workspace, capture_output=True, text=True, timeout=30,
            )
            if result.returncode:
                raise AssertionError(f"Could not generate {fixture}:\n{result.stdout}{result.stderr}")
            (cls.workspace / summary).write_text(result.stdout, encoding="utf-8")
        cls.hashes = tuple(hashlib.sha256((cls.workspace / fixture).read_bytes()).hexdigest() for fixture in cls.fixtures)
        if len(set(cls.hashes)) != len(cls.fixtures):
            raise AssertionError("Provenance fixtures must have different SHA-256 digests")

    def compare(self, name, fixtures, summaries=(), *, rule_source=(), promtool=None, cwd=None):
        report = self.workspace / f"{name}.report.json"
        command = [sys.executable, CLI, "compare", *fixtures, "--json-report", report,
                   "--promtool", promtool or self.promtool]
        command.extend(rule_source or ("--before", BEFORE, "--after", AFTER))
        for path in summaries:
            command.extend(("--capture-summary", path))
        result = subprocess.run(command, cwd=cwd or self.workspace, capture_output=True, text=True, timeout=30)
        return result, report

    def assert_preflight_error(self, name, fixtures, summaries, diagnostic, *, rule_source=()):
        marker = self.workspace / f"{name}.ran-promtool"
        executable = self.workspace / f"{name}.promtool"
        executable.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        executable.chmod(0o700)

        result, report = self.compare(name, fixtures, summaries, rule_source=rule_source, promtool=executable)

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertRegex(result.stderr, diagnostic)
        self.assertEqual(result.stdout, "")
        self.assertFalse(report.exists())
        self.assertFalse(marker.exists(), "provenance error should prevent starting promtool")

    def test_linked_summaries_verify_in_fixture_order(self):
        result, report_path = self.compare("verified", self.fixtures, self.summaries)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertIn("Verified SHA-256", result.stdout)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertNotIn("fixture_commit", report)
        self.assertEqual(
            [(item["path"], item["capture_summary"], item["sha256"]) for item in report["fixtures"]],
            list(zip(self.fixtures, self.summaries, self.hashes)),
        )

        default, default_path = self.compare("unverified", self.fixtures)

        self.assertEqual(default.returncode, 0, f"{default.stdout}\n{default.stderr}")
        default_report = json.loads(default_path.read_text(encoding="utf-8"))
        self.assertNotIn("fixture_commit", default_report)
        for item in default_report["fixtures"]:
            self.assertNotIn("sha256", item)
            self.assertNotIn("capture_summary", item)

    def test_swapped_summaries_fail_before_promtool(self):
        self.assert_preflight_error("swapped", self.fixtures, self.summaries[::-1], r"(?i)sha-?256|digest")

    def test_incomplete_summary_list_fails_before_promtool(self):
        self.assert_preflight_error("partial", self.fixtures, self.summaries[:1], r"(?i)capture.summary")

    def test_schema_version_must_be_integer_one(self):
        data = json.loads((self.workspace / self.summaries[0]).read_text(encoding="utf-8"))
        for index, version in enumerate((True, 1.0, "1", 2)):
            with self.subTest(version=version):
                path = self.workspace / f"wrong-schema-{index}.json"
                path.write_text(json.dumps({**data, "schema_version": version}), encoding="utf-8")
                self.assert_preflight_error(f"schema-{index}", self.fixtures[:1], (path,), r"(?i)schema.version")

    def test_same_json_with_different_bytes_fails_verification(self):
        path = self.workspace / self.fixtures[0]
        content = path.read_bytes()
        self.addCleanup(path.write_bytes, content)
        path.write_bytes(content + b"\n")

        self.assert_preflight_error("changed-bytes", self.fixtures[:1], self.summaries[:1], r"(?i)sha-?256|digest")

    def test_fixture_ref_requires_git_rule_comparison(self):
        self.assert_preflight_error(
            "file-rules", self.fixtures[:1], (), r"(?i)fixture-ref|git",
            rule_source=("--before", BEFORE, "--after", AFTER, "--fixture-ref", "HEAD"),
        )

    @unittest.skipUnless(shutil.which("git"), "Git is required for ref comparison")
    def test_fixture_and_summary_are_read_from_same_git_commit(self):
        repo = self.workspace / "repo"
        repo.mkdir()

        def git(*arguments):
            command = [
                "git", "-C", repo, "-c", "user.name=Integration Test", "-c", "user.email=test@example.invalid",
                "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", "-c", f"core.hooksPath={os.devnull}", *arguments,
            ]
            return subprocess.check_output(command, text=True, stderr=subprocess.PIPE, timeout=30).strip()

        git("init", "--quiet")
        rule_path = "rules/payment alert.yml"
        (repo / rule_path).parent.mkdir()
        shutil.copyfile(BEFORE, repo / rule_path)
        for path in (*self.fixtures, *self.summaries):
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.workspace / path, repo / path)
        git("add", "--", ".")
        git("commit", "--quiet", "-m", "Capture both historical fixtures")
        fixture_commit = git("rev-parse", "HEAD")

        (repo / self.fixtures[0]).write_text("{unfinished fixture", encoding="utf-8")
        (repo / self.summaries[1]).unlink()
        git("add", "--", ".")
        git("commit", "--quiet", "-m", "Remove usable historical data from later revisions")
        before = git("rev-parse", "HEAD")

        shutil.copyfile(AFTER, repo / rule_path)
        git("add", "--", rule_path)
        git("commit", "--quiet", "-m", "Fix alert")
        after = git("rev-parse", "HEAD")
        (repo / self.fixtures[1]).unlink()
        (repo / self.summaries[0]).write_text("{unfinished summary", encoding="utf-8")
        dirty = git("status", "--porcelain=v1")
        rule_source = (
            "--before-ref", "HEAD^", "--after-ref", "HEAD", "--rule-file", rule_path,
            "--fixture-ref", "HEAD~2", "--repo", repo,
        )

        result, report_path = self.compare(
            "pinned", self.fixtures, self.summaries, rule_source=rule_source, cwd=(repo / rule_path).parent,
        )

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertIn(f"Loaded fixtures from Git commit `{fixture_commit}`", result.stdout)
        self.assertIn("Verified SHA-256", result.stdout)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["fixture_commit"], fixture_commit)
        self.assertEqual(report["commits"], {"before": before, "after": after})
        self.assertEqual(
            [(item["path"], item["capture_summary"], item["sha256"]) for item in report["fixtures"]],
            list(zip(self.fixtures, self.summaries, self.hashes)),
        )

        pinned, pinned_path = self.compare(
            "pinned-without-summaries", self.fixtures, rule_source=rule_source, cwd=(repo / rule_path).parent,
        )
        self.assertEqual(pinned.returncode, 0, f"{pinned.stdout}\n{pinned.stderr}")
        pinned_report = json.loads(pinned_path.read_text(encoding="utf-8"))
        self.assertEqual(pinned_report["fixture_commit"], fixture_commit)
        self.assertEqual([item["sha256"] for item in pinned_report["fixtures"]], list(self.hashes))
        for item in pinned_report["fixtures"]:
            self.assertNotIn("capture_summary", item)

        self.assertEqual(git("status", "--porcelain=v1"), dirty)
        self.assertEqual(git("rev-parse", "HEAD"), after)


if __name__ == "__main__":
    unittest.main()
