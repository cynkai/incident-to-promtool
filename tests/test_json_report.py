from copy import deepcopy
import json
import os
from pathlib import Path
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
ALERT = "PaymentErrorsHigh"


class JsonReportIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        promtool = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        if promtool is None:
            raise unittest.SkipTest("promtool unavailable; set PROMTOOL to its path")
        cls.promtool = Path(promtool).resolve()
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.fixture = "payment incident.test.yml"
        result = subprocess.run(
            [
                sys.executable, CLI, DEMO / "demo.json", "--matrix", DEMO / "incident.matrix.json",
                "--output", cls.fixture,
            ],
            cwd=cls.workspace, capture_output=True, text=True, timeout=30,
        )
        if result.returncode:
            raise AssertionError(f"Could not generate demo fixture:\n{result.stdout}{result.stderr}")

    def compare(self, target, *fixtures, rule_source=(), gate=None):
        command = [sys.executable, CLI, "compare", *fixtures, "--json-report", target, "--promtool", self.promtool]
        command.extend(rule_source or ("--before", BEFORE, "--after", AFTER))
        if gate is not None:
            command.extend(("--gate", gate))
        return subprocess.run(command, cwd=self.workspace, capture_output=True, text=True, timeout=30)

    def assert_checkpoint(self, checkpoint, group, alertname, change, before, after):
        self.assertEqual(checkpoint["group"], group)
        self.assertEqual(checkpoint["alertname"], alertname)
        self.assertEqual(checkpoint["offset_ms"], 420_000)
        self.assertEqual(checkpoint["change"], change)
        for field, expected in (("before_diagnostic", before), ("after_diagnostic", after)):
            if expected:
                self.assertIsInstance(checkpoint[field], str)
                self.assertIn(alertname, checkpoint[field])
            else:
                self.assertIsNone(checkpoint[field])

    def test_pass_writes_v1_json_that_agrees_with_markdown(self):
        target = self.workspace / "passed report.json"

        result = self.compare(target, self.fixture)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        report = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["gate"], {"mode": "strict", "passed": True})
        self.assertIsNone(report["commits"])
        self.assertEqual(report["summary"], {
            "before": {"matched": 1, "total": 2}, "after": {"matched": 2, "total": 2},
            "newly_failed": 0, "fixed": 1, "still_failing": 0,
        })
        fixture, = report["fixtures"]
        self.assertEqual(fixture["path"], self.fixture)
        self.assertEqual(fixture["before"], report["summary"]["before"])
        self.assertEqual(fixture["after"], report["summary"]["after"])
        change, = fixture["changes"]
        self.assert_checkpoint(change, 1, ALERT, "fixed", before=True, after=False)
        self.assertIn("Gate `strict`: **Passed**", result.stdout)
        self.assertIn("| Before | Failed | 1/2 |", result.stdout)
        self.assertIn("| After | Passed | 2/2 |", result.stdout)
        self.assertIn(f"| <code>{self.fixture}</code> | 1 | <code>{ALERT}</code> | 420s | Fixed |", result.stdout)

    def test_no_mismatches_still_writes_complete_report(self):
        target = self.workspace / "no changes.json"

        result = self.compare(target, self.fixture, rule_source=("--before", AFTER, "--after", AFTER))

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        report = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"], {
            "before": {"matched": 2, "total": 2}, "after": {"matched": 2, "total": 2},
            "newly_failed": 0, "fixed": 0, "still_failing": 0,
        })
        fixture, = report["fixtures"]
        self.assertEqual(fixture["changes"], [])

    def test_failed_regression_gate_writes_all_checkpoint_transitions(self):
        data = json.loads((self.workspace / self.fixture).read_text(encoding="utf-8"))
        original, = data["tests"]
        new_failure = deepcopy(original)
        new_failure["alert_rule_test"][-1]["exp_alerts"] = []
        persistent = deepcopy(original)
        persistent["alert_rule_test"][-1]["alertname"] = "AlwaysMissing"
        data["tests"] = [new_failure, persistent]
        fixture = self.workspace / "mixed.test.yml"
        fixture.write_text(json.dumps(data), encoding="utf-8")
        target = self.workspace / "failed.json"

        result = self.compare(target, self.fixture, fixture.name, gate="regressions")

        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        report = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(report["gate"], {"mode": "regressions", "passed": False})
        self.assertEqual(report["summary"], {
            "before": {"matched": 4, "total": 6}, "after": {"matched": 4, "total": 6},
            "newly_failed": 1, "fixed": 1, "still_failing": 1,
        })
        original_report, fixture_report = report["fixtures"]
        self.assertEqual(original_report["path"], self.fixture)
        self.assertEqual(fixture_report["path"], fixture.name)
        self.assertEqual(original_report["before"], {"matched": 1, "total": 2})
        self.assertEqual(original_report["after"], {"matched": 2, "total": 2})
        self.assertEqual(fixture_report["before"], {"matched": 3, "total": 4})
        self.assertEqual(fixture_report["after"], {"matched": 2, "total": 4})
        fixed, = original_report["changes"]
        regressed, still_failing = fixture_report["changes"]
        self.assert_checkpoint(fixed, 1, ALERT, "fixed", before=True, after=False)
        self.assert_checkpoint(regressed, 1, ALERT, "newly_failed", before=False, after=True)
        self.assert_checkpoint(still_failing, 2, "AlwaysMissing", "still_failing", before=True, after=True)
        self.assertIn("Gate `regressions`: **Failed**", result.stdout)
        for name in ("Before", "After"):
            self.assertIn(f"| {name} | Failed | 4/6 |", result.stdout)

    @unittest.skipUnless(shutil.which("git"), "Git is required for ref comparison")
    def test_git_ref_report_contains_resolved_commit_ids(self):
        repository = self.workspace / "repo"
        repository.mkdir()

        def git(*arguments):
            command = [
                "git", "-C", repository, "-c", "user.name=Integration Test", "-c", "user.email=test@example.invalid",
                "-c", "commit.gpgsign=false", "-c", f"core.hooksPath={os.devnull}", *arguments,
            ]
            return subprocess.check_output(command, text=True, stderr=subprocess.PIPE, timeout=30).strip()

        git("init", "--quiet")
        for source in (BEFORE, AFTER):
            shutil.copyfile(source, repository / "alerts.yml")
            git("add", "--", "alerts.yml")
            git("commit", "--quiet", "-m", f"Add {source.name}")
        before = git("rev-parse", "HEAD^")
        after = git("rev-parse", "HEAD")
        target = self.workspace / "commits.json"

        result = self.compare(
            target, self.fixture, rule_source=(
                "--before-ref", "HEAD^", "--after-ref", "HEAD", "--rule-file", "alerts.yml", "--repo", repository,
            ),
        )

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        report = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(report["commits"], {"before": before, "after": after})
        self.assertIn(f"Compared Git commits `{before}` and `{after}`", result.stdout)

    def test_existing_report_is_preserved_without_printing_report(self):
        target = self.workspace / "existing.json"
        original = b"Do not replace this file\n"
        target.write_bytes(original)

        result = self.compare(target, self.fixture)

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(target.read_bytes(), original)
        self.assertNotIn("## Prometheus alert comparison", result.stdout)
        self.assertIn(target.name, result.stderr)

    def test_operational_error_does_not_create_either_report(self):
        malformed = self.workspace / "malformed.rules.yml"
        malformed.write_text("groups: [\n", encoding="utf-8")
        target = self.workspace / "error.json"

        result = self.compare(target, self.fixture, rule_source=("--before", BEFORE, "--after", malformed))

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertFalse(target.exists())
        self.assertNotIn("## Prometheus alert comparison", result.stdout)


if __name__ == "__main__":
    unittest.main()
