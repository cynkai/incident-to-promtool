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
from xml.etree import ElementTree
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
ALERT = "PaymentErrorsHigh"
ARCHIVED_RULE = "rules/rules-1.yml"
SLOW = "current slow.rules.yml"
FAST = "historical fast.rules.yml"


class CompareBundleTimelineIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(executable).resolve() if executable else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        shutil.copyfile(DEMO / "before.rules.yml", cls.workspace / SLOW)
        shutil.copyfile(DEMO / "after.rules.yml", cls.workspace / FAST)
        auxiliary = "reporting.rules.yml"
        (cls.workspace / auxiliary).write_text(
            "groups:\n- name: reporting\n  rules:\n  - record: report_flag\n    expr: vector(1)\n",
            encoding="utf-8",
        )

        config = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        config["expectations"][-1]["at"] = "10m"
        config_path = cls.workspace / "late checkpoint.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        cls.fast = "fast [archive]/payment & logs.zip"
        cls.slow = "slow [archive]/payment & logs.zip"
        cls.fixture_hashes = {}
        for archive, rule_args in ((cls.fast, ("--rule-file", FAST)),
                                   (cls.slow, ("--rule-file", SLOW, "--rule-file", auxiliary))):
            (cls.workspace / archive).parent.mkdir()
            result = cls.cli(
                "bundle", config_path, "--matrix", DEMO / "incident.matrix.json", "--output", archive, *rule_args,
            )
            if result.returncode:
                raise AssertionError(f"Could not create {archive}:\n{result.stdout}{result.stderr}")
            with ZipFile(cls.workspace / archive) as source:
                cls.fixture_hashes[archive] = hashlib.sha256(source.read("incident.test.yml")).hexdigest()

    @classmethod
    def cli(cls, *arguments):
        return subprocess.run(
            [sys.executable, CLI, *arguments], cwd=cls.workspace, capture_output=True, text=True, timeout=30,
        )

    def timing(self, *, alert=ALERT, end="10m", limit="1m"):
        return ("--timeline-alertname", alert, "--timeline-end", end, "--timeline-max-delay", limit)

    def compare(self, name, archives, *options, promtool=None):
        if promtool is None and self.promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        machine = self.workspace / f"{name}.report.json"
        junit = self.workspace / f"{name}.report.xml"
        result = self.cli(
            "compare-bundle", *archives, "--promtool", promtool or self.promtool,
            "--json-report", machine, "--junit-report", junit, *options,
        )
        return result, machine, junit

    def assert_timeline(
        self, outcome, *, archive, archived_rules, baseline_source, rule_files, before_offset, checkpoint_count=2,
        fixture_commit=None, checksum=None,
    ):
        result, machine, junit = outcome
        delta = 570_000 - before_offset
        timing_passed = delta <= 60_000
        self.assertEqual(result.returncode, int(not timing_passed), f"{result.stdout}\n{result.stderr}")
        self.assertRegex(result.stdout, r"Gate .*strict.*Passed")
        self.assertIn("## Prometheus alert firing timeline", result.stdout)
        self.assertIn(archive, unescape(result.stdout))

        report = json.loads(machine.read_text(encoding="utf-8"))
        self.assertEqual(report["gate"], {"mode": "strict", "passed": True})
        for side in ("before", "after"):
            self.assertEqual(report["summary"][side], {"matched": checkpoint_count, "total": checkpoint_count})
        timeline = report["timeline"]
        self.assertEqual(timeline["bundle"], {"path": archive, "rule_files": list(archived_rules)})
        self.assertEqual(timeline["baseline_source"], baseline_source)
        self.assertEqual(timeline["rule_files"], rule_files)
        fixture_path = f"{archive}!incident.test.yml"
        self.assertEqual(timeline["fixture_path"], fixture_path)
        self.assertEqual(timeline["capture_summary"], f"{archive}!capture.json")
        expected_hash = checksum if checksum is not None else self.fixture_hashes[archive]
        self.assertEqual(timeline["fixture_sha256"], expected_hash)
        if fixture_commit is None:
            self.assertNotIn("fixture_commit", timeline)
        else:
            self.assertEqual(timeline["fixture_commit"], fixture_commit)
        group, = timeline["groups"]
        self.assertEqual(group["before"]["first_firing_offset_ms"], before_offset)
        self.assertEqual(group["after"]["first_firing_offset_ms"], 570_000)
        self.assertEqual(group["first_firing_delta_ms"], delta)
        self.assertEqual(timeline["gate"], {
            "mode": "max-delay", "max_delay_ms": 60_000, "passed": timing_passed, "checked_groups": 1,
            "groups": [{
                "group": 1, "status": "passed" if timing_passed else "delayed",
                "before_first_firing_offset_ms": before_offset, "after_first_firing_offset_ms": 570_000,
                "first_firing_delta_ms": delta,
            }],
        })

        root = ElementTree.parse(junit).getroot()
        self.assertEqual(root.get("tests"), str(checkpoint_count + 1))
        self.assertEqual(root.get("failures"), str(int(not timing_passed)))
        timing_suite = root.findall("testsuite")[-1]
        self.assertEqual(timing_suite.get("name"), "Alert firing delay")
        case, = timing_suite.findall("testcase")
        self.assertEqual(case.get("classname"), fixture_path)
        self.assertEqual(case.find("failure") is None, timing_passed)
        return report

    def test_explicit_baseline_replaces_archived_rule_for_timing_only(self):
        archive = self.workspace / self.fast
        original = archive.read_bytes()
        archived = self.compare("archived", (self.fast,), "--after", SLOW, *self.timing())
        explicit = self.compare("explicit", (self.fast,), "--before", SLOW, "--after", SLOW, *self.timing())

        report = self.assert_timeline(
            archived, archive=self.fast, archived_rules=(ARCHIVED_RULE,), baseline_source="bundle",
            rule_files={"before": [ARCHIVED_RULE], "after": [SLOW]}, before_offset=330_000,
        )
        self.assertEqual(report["timeline"]["bundle"], report["bundle"])
        self.assertNotIn("rule_files", report)
        report = self.assert_timeline(
            explicit, archive=self.fast, archived_rules=(ARCHIVED_RULE,), baseline_source="rules",
            rule_files={"before": [SLOW], "after": [SLOW]}, before_offset=570_000,
        )
        self.assertEqual(report["timeline"]["bundle"], report["bundle"])
        self.assertEqual(report["timeline"]["rule_files"], report["rule_files"])
        self.assertEqual(archive.read_bytes(), original)

    def test_batch_probes_each_selected_archive_with_its_own_rules(self):
        both = (self.slow, self.fast)
        selections = (
            ("batch-fast", self.fast, 1, (ARCHIVED_RULE,), 330_000),
            ("batch-slow", self.slow, 0, (ARCHIVED_RULE, "rules/rules-2.yml"), 570_000),
        )
        for name, selected, index, archived_rules, before_offset in selections:
            with self.subTest(selected=selected):
                outcome = self.compare(
                    name, both, "--after", SLOW, *self.timing(), "--timeline-bundle", selected,
                )

                report = self.assert_timeline(
                    outcome, archive=selected, archived_rules=archived_rules, baseline_source="bundle",
                    rule_files={"before": list(archived_rules), "after": [SLOW]},
                    before_offset=before_offset, checkpoint_count=4,
                )
                self.assertNotIn("bundle", report)
                self.assertEqual([bundle["path"] for bundle in report["bundles"]], list(both))
                self.assertEqual(report["timeline"]["bundle"], report["bundles"][index])

    @unittest.skipUnless(shutil.which("git"), "Git is required for ref comparison")
    def test_git_timing_keeps_bundle_and_candidate_rule_commit_provenance(self):
        repo = self.workspace / "timeline bundle git"
        repo.mkdir()

        def git(*arguments):
            return subprocess.check_output(
                [
                    "git", "-C", repo, "-c", "user.name=Integration Test", "-c", "user.email=test@example.invalid",
                    "-c", "commit.gpgsign=false", "-c", f"core.hooksPath={os.devnull}", *arguments,
                ],
                text=True, stderr=subprocess.PIPE, timeout=30,
            ).strip()

        archive = "incident files/capture [payment].zip"
        after_rule = "proposed rules/payment [slow].yml"
        git("init", "--quiet")
        (repo / archive).parent.mkdir()
        shutil.copyfile(self.workspace / self.fast, repo / archive)
        git("add", "--", archive)
        git("commit", "--quiet", "-m", "Record fast archived rules")
        before = git("rev-parse", "HEAD")

        (repo / after_rule).parent.mkdir()
        shutil.copyfile(self.workspace / SLOW, repo / after_rule)
        (repo / archive).write_bytes(b"unusable archive in the candidate commit\n")
        git("add", "--", archive, after_rule)
        git("commit", "--quiet", "-m", "Propose the slower rule")
        after = git("rev-parse", "HEAD")
        (repo / archive).unlink()
        (repo / after_rule).write_bytes(b"groups: [unusable working rule\n")
        dirty = git("status", "--porcelain=v1")

        outcome = self.compare(
            "git", (archive,), "--repo", repo, "--bundle-ref", "HEAD^", "--after-ref", "HEAD",
            "--rule-file", after_rule, *self.timing(),
        )

        report = self.assert_timeline(
            outcome, archive=archive, archived_rules=(ARCHIVED_RULE,), baseline_source="bundle",
            rule_files={"before": [ARCHIVED_RULE], "after": [after_rule]}, before_offset=330_000,
            fixture_commit=before, checksum=self.fixture_hashes[self.fast],
        )
        self.assertEqual(report["commits"], {"before": before, "after": after})
        self.assertEqual(report["timeline"]["bundle"], report["bundle"])
        self.assertEqual(report["timeline"]["commits"], report["commits"])
        self.assertEqual(git("rev-parse", "HEAD"), after)
        self.assertEqual(git("status", "--porcelain=v1"), dirty)

    def test_invalid_timing_arguments_do_not_replay_or_produce_reports(self):
        marker = self.workspace / "invalid options ran promtool"
        stub = self.workspace / "bundle preflight promtool"
        stub.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        stub.chmod(0o700)
        single = (self.fast,)
        batch = (self.slow, self.fast)
        cases = (
            ("incomplete", single, ("--timeline-end", "10m"), r"(?i)required together"),
            ("only-selector", single, ("--timeline-bundle", self.fast), r"(?i)timeline"),
            ("missing-selector", batch, self.timing(), r"(?i)timeline-bundle"),
            ("different-spelling", batch, (*self.timing(), "--timeline-bundle", f"./{self.fast}"), r"(?i)bundle"),
            ("wrong-selector-type", single, (*self.timing(), "--timeline-fixture", self.fast),
             r"(?i)unrecognized arguments.*--timeline-fixture"),
            ("absent-alert", single, self.timing(alert="MissingAlert"), r"(?i)checkpoint|MissingAlert"),
            ("unaligned-end", single, self.timing(end="1s"), r"(?i)align|tick|evaluation"),
        )
        for name, archives, options, diagnostic in cases:
            with self.subTest(case=name):
                result, machine, junit = self.compare(name, archives, "--after", SLOW, *options, promtool=stub)

                self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
                self.assertEqual(result.stdout, "")
                self.assertRegex(result.stderr, diagnostic)
                for path in (marker, machine, junit):
                    self.assertFalse(path.exists(), f"failed preflight should not create {path.name}")


if __name__ == "__main__":
    unittest.main()
