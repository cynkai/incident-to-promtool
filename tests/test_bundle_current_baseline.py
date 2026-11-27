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
from zipfile import BadZipFile, ZipFile


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
ARCHIVED_RULE_PATHS = ["rules/rules-1.yml", "rules/rules-2.yml"]


class CurrentBundleBaselineIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(executable).resolve() if executable else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.auxiliary = cls.workspace / "auxiliary rules.yml"
        cls.auxiliary.write_text(
            "groups:\n- name: auxiliary\n  rules:\n  - alert: AuxiliaryReady\n    expr: vector(1)\n", encoding="utf-8",
        )
        before = cls.workspace / "current payment rules.yml"
        after = cls.workspace / "regressed payment rules.yml"
        shutil.copyfile(DEMO / "after.rules.yml", before)
        shutil.copyfile(DEMO / "before.rules.yml", after)
        cls.baseline = (before, cls.auxiliary)
        cls.candidate = (after, cls.auxiliary)
        cls.config = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        cls.config["expectations"].append({"at": "90s", "alertname": "AuxiliaryReady", "alerts": [{"labels": {}}]})
        cls.archive = cls.create_bundle("historical incident", cls.config)
        with ZipFile(cls.archive) as bundle:
            cls.fixture_sha = hashlib.sha256(bundle.read("incident.test.yml")).hexdigest()

    @classmethod
    def create_bundle(cls, name, config):
        config_path = cls.workspace / f"{name}.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        archive = cls.workspace / f"{name}.zip"
        result = subprocess.run(
            [
                sys.executable, CLI, "bundle", config_path, "--matrix", DEMO / "incident.matrix.json", "--output", archive,
                "--rule-file", cls.candidate[0], "--rule-file", cls.auxiliary,
            ],
            cwd=cls.workspace, capture_output=True, text=True, timeout=30,
        )
        if result.returncode:
            raise AssertionError(f"Could not generate historical archive:\n{result.stdout}{result.stderr}")
        return archive

    @staticmethod
    def file_options(option, paths):
        return tuple(value for path in paths for value in (option, path))

    def local_options(self, use_current_baseline=False):
        before = self.file_options("--before", (path.name for path in self.baseline)) if use_current_baseline else ()
        after = self.file_options("--after", (path.name for path in self.candidate))
        return (*before, *after)

    def compare(self, name, *options, archives=None, cwd=None, executable=None):
        if executable is None and self.promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        report = self.workspace / f"{name}.report.json"
        junit = self.workspace / f"{name}.report.xml"
        command = [
            sys.executable, CLI, "compare-bundle", *(archives if archives is not None else (self.archive.name,)),
            "--gate", "regressions", "--promtool", executable or self.promtool,
            "--json-report", report, "--junit-report", junit, *options,
        ]
        result = subprocess.run(command, cwd=cwd or self.workspace, capture_output=True, text=True, timeout=30)
        return result, report, junit

    def assert_preflight_error(self, name, diagnostic, *options, archives=None):
        marker = self.workspace / f"{name}.ran-promtool"
        fake = self.workspace / f"{name}.promtool"
        fake.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        fake.chmod(0o700)

        result, report, junit = self.compare(name, *options, archives=archives, executable=fake)

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertRegex(result.stderr, diagnostic)
        self.assertEqual(result.stdout, "")
        self.assertFalse(report.exists())
        self.assertFalse(junit.exists())
        self.assertFalse(marker.exists(), "operational errors must be reported before replay")

    def assert_new_regression(self, result, report_path, archive):
        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertIn("Gate `regressions`: **Failed**", result.stdout)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["gate"], {"mode": "regressions", "passed": False})
        self.assertEqual(report["summary"], {
            "before": {"matched": 3, "total": 3}, "after": {"matched": 2, "total": 3},
            "newly_failed": 1, "fixed": 0, "still_failing": 0,
        })
        self.assertEqual(report["bundle"], {"path": archive, "rule_files": ARCHIVED_RULE_PATHS})
        fixture, = report["fixtures"]
        self.assertEqual(fixture["path"], f"{archive}!incident.test.yml")
        self.assertEqual(fixture["capture_summary"], f"{archive}!capture.json")
        self.assertEqual(fixture["sha256"], self.fixture_sha)
        change, = fixture["changes"]
        self.assertEqual((change["alertname"], change["offset_ms"], change["change"]), ("PaymentErrorsHigh", 420_000, "newly_failed"))
        return report

    def test_current_local_baseline_detects_a_regression_the_archive_tolerates(self):
        original = self.archive.read_bytes()
        historical, historical_report, _ = self.compare("historical", *self.local_options())
        current, current_report, _ = self.compare("current", *self.local_options(use_current_baseline=True))

        self.assertEqual(historical.returncode, 0, f"{historical.stdout}\n{historical.stderr}")
        old_report = json.loads(historical_report.read_text(encoding="utf-8"))
        self.assertEqual(old_report["summary"]["still_failing"], 1)
        self.assertEqual(old_report["summary"]["newly_failed"], 0)
        self.assertNotIn("rule_files", old_report)
        report = self.assert_new_regression(current, current_report, self.archive.name)
        self.assertIsNone(report["commits"])
        self.assertEqual(report["rule_files"], {
            "before": [path.name for path in self.baseline], "after": [path.name for path in self.candidate],
        })
        self.assertEqual(old_report["fixtures"][0]["sha256"], report["fixtures"][0]["sha256"])
        self.assertEqual(self.archive.read_bytes(), original)

    def test_local_override_applies_to_every_bundle_in_a_batch(self):
        second = self.create_bundle("auxiliary only", {**self.config, "expectations": self.config["expectations"][-1:]})
        result, report_path, _ = self.compare(
            "batch-current", *self.local_options(use_current_baseline=True), archives=(self.archive.name, second.name),
        )

        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["before"], {"matched": 4, "total": 4})
        self.assertEqual(report["summary"]["after"], {"matched": 3, "total": 4})
        self.assertEqual(report["summary"]["newly_failed"], 1)
        self.assertEqual([item["path"] for item in report["bundles"]], [self.archive.name, second.name])
        self.assertEqual(report["fixtures"][1]["changes"], [])

    @unittest.skipUnless(shutil.which("git"), "Git is required for ref comparison")
    def test_git_current_baseline_uses_base_zip_and_committed_rules(self):
        repo = self.workspace / "git repository with spaces"
        repo.mkdir()

        def git(*arguments):
            command = [
                "git", "-C", repo, "-c", "user.name=Integration Test", "-c", "user.email=test@example.invalid",
                "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", "-c", f"core.hooksPath={os.devnull}", *arguments,
            ]
            return subprocess.check_output(command, text=True, stderr=subprocess.PIPE, timeout=30).strip()

        def copy_rules(paths, sources):
            for path, source in zip(paths, sources):
                (repo / path).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, repo / path)

        git("init", "--quiet")
        archive = "captures/payment [pinned].zip"
        (repo / archive).parent.mkdir()
        shutil.copyfile(self.archive, repo / archive)
        before_paths = ("base rules/payment [current].yml", "base rules/auxiliary [current].yml")
        after_paths = ("proposed/rules/payment [candidate].yml", "proposed/rules/auxiliary [candidate].yml")
        copy_rules(before_paths, self.baseline)
        git("add", "--", ".")
        git("commit", "--quiet", "-m", "Pin original capture and current baseline")
        before = git("rev-parse", "HEAD")

        for path in before_paths:
            (repo / path).unlink()
        copy_rules(after_paths, self.candidate)
        (repo / archive).write_bytes(b"invalid archive in candidate revision\n")
        git("add", "--", ".")
        git("commit", "--quiet", "-m", "Move rules and regress payment detection")
        after = git("rev-parse", "HEAD")
        (repo / archive).write_bytes(b"different invalid archive in working tree\n")
        (repo / after_paths[0]).write_bytes(b"groups: [invalid staged rule\n")
        git("add", "--", after_paths[0])
        (repo / after_paths[0]).write_bytes(b"groups: [invalid working rule\n")

        def checkout_state():
            return (git("rev-parse", "HEAD"), git("symbolic-ref", "HEAD"), git("status", "--porcelain=v1"),
                    git("diff", "--cached", "--binary"), git("diff", "--binary"))

        dirty = checkout_state()
        invocations = (
            ("nested", (repo / after_paths[0]).parent, ("--bundle-ref", "HEAD^", "--after-ref", "HEAD")),
            ("outside", self.workspace, ("--repo", repo, "--bundle-ref", before, "--after-ref", after)),
        )
        for name, cwd, refs in invocations:
            with self.subTest(cwd=name):
                result, report_path, _ = self.compare(
                    f"git-current-{name}", *refs, *self.file_options("--before-rule-file", before_paths),
                    *self.file_options("--after-rule-file", after_paths), archives=(archive,), cwd=cwd,
                )

                report = self.assert_new_regression(result, report_path, archive)
                self.assertEqual(report["commits"], {"before": before, "after": after})
                self.assertEqual(report["rule_files"], {"before": list(before_paths), "after": list(after_paths)})
                self.assertEqual(checkout_state(), dirty)

    def rewrite_archive(self, name, member, contents):
        output = self.workspace / name
        with ZipFile(self.archive) as original, ZipFile(output, "w") as changed:
            for entry in original.infolist():
                data = contents if entry.filename == member else original.read(entry)
                changed.writestr(entry.filename, data)
        return output

    def test_unused_archived_baseline_is_not_read_but_remains_checked_by_default(self):
        member = ARCHIVED_RULE_PATHS[0]
        sentinel = b"bad-archived-rule-crc\n"
        archive = self.rewrite_archive("unreadable archived rules.zip", member, sentinel)
        data = archive.read_bytes()
        self.assertEqual(data.count(sentinel), 1)
        archive.write_bytes(data.replace(sentinel, b"bad-archived-rule-CRC\n", 1))
        with ZipFile(archive) as bundle, self.assertRaises(BadZipFile):
            bundle.read(member)

        result, report_path, _ = self.compare(
            "unused-baseline", *self.local_options(use_current_baseline=True), archives=(archive.name,),
        )
        self.assert_new_regression(result, report_path, archive.name)
        self.assert_preflight_error("used-baseline", r"(?i)crc|zip|archive", *self.local_options(), archives=(archive.name,))

    def test_external_baseline_does_not_skip_fixture_checksum(self):
        with ZipFile(self.archive) as bundle:
            fixture = bundle.read("incident.test.yml")
        altered = self.rewrite_archive("altered fixture.zip", "incident.test.yml", fixture + b"\n")

        self.assert_preflight_error(
            "fixture-checksum", r"(?i)sha-?256|digest|hash",
            *self.local_options(use_current_baseline=True), archives=(altered.name,),
        )

    def test_mixed_and_missing_rule_options_are_rejected(self):
        refs = ("--bundle-ref", "HEAD^", "--after-ref", "HEAD")
        scoped = ("--before-rule-file", "before.yml", "--after-rule-file", "after.yml")
        cases = (
            ("local-without-after", ("--before", self.baseline[0].name), r"(?i)requires|provide"),
            ("mixed-local-git", (*refs, *scoped, "--before", self.baseline[0].name), r"(?i)choose|either|mix"),
            ("mixed-shared-git", (*refs, *scoped, "--rule-file", "shared.yml"), r"(?i)choose|either|mix"),
            ("missing-after-scope", (*refs, *scoped[:2]), r"(?i)provide both|requires"),
            ("missing-before-scope", (*refs, *scoped[2:]), r"(?i)provide both|requires"),
            ("missing-bundle-ref", ("--after-ref", "HEAD", *scoped), r"(?i)requires|provide"),
        )
        for name, options, diagnostic in cases:
            with self.subTest(name=name):
                self.assert_preflight_error(name, diagnostic, *options)


if __name__ == "__main__":
    unittest.main()
