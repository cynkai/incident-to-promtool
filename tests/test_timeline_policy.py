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
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
FAST = DEMO / "after.rules.yml"
SLOW = DEMO / "before.rules.yml"
ALERT = "PaymentErrorsHigh"


def check(*, source=None, limit="240s", end="10m"):
    result = {"alertname": ALERT, "end": end, "max_delay": limit}
    if source is not None:
        result["source"] = source
    return result


def policy_bytes(*checks):
    return (json.dumps({"schema_version": 1, "checks": checks}, indent=2) + "\n").encode("utf-8")


class TimelinePolicyIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(executable).resolve() if executable else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        cls.first = "cards/payment & logs.test.yml"
        cls.second = "refunds/payment & logs.test.yml"
        cls.config_path = cls.workspace / "10 minute incident.json"
        config = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        config["expectations"][-1]["at"] = "10m"
        cls.config_path.write_text(json.dumps(config), encoding="utf-8")
        for fixture in (cls.first, cls.second):
            (cls.workspace / fixture).parent.mkdir()
        generated = cls.cli(
            cls.config_path, "--matrix", DEMO / "incident.matrix.json", "--rule-file", FAST, "--output", cls.first,
        )
        if generated.returncode:
            raise AssertionError(f"Could not generate a late checkpoint fixture:\n{generated.stdout}{generated.stderr}")
        shutil.copyfile(cls.workspace / cls.first, cls.workspace / cls.second)

    @classmethod
    def cli(cls, *arguments, cwd=None):
        return subprocess.run(
            [sys.executable, CLI, *arguments], cwd=cwd or cls.workspace, capture_output=True, text=True, timeout=30,
        )

    def compare(self, name, sources, path, *options, command="compare", promtool=None, cwd=None):
        if promtool is None and self.promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        report = self.workspace / f"{name}.report.json"
        junit = self.workspace / f"{name}.report.xml"
        result = self.cli(
            command, *sources, "--timeline-policy", path, "--promtool", promtool or self.promtool,
            "--json-report", report, "--junit-report", junit, *options, cwd=cwd,
        )
        return result, report, junit

    def assert_policy(self, outcome, *, passed, path, contents, checkpoints, policy_commit=None):
        result, machine, junit = outcome
        self.assertEqual(result.returncode, int(not passed), f"{result.stdout}\n{result.stderr}")
        report = json.loads(machine.read_text(encoding="utf-8"))
        self.assertNotIn("timeline", report)
        self.assertEqual(report["gate"], {"mode": "strict", "passed": True})
        self.assertEqual(report["summary"]["after"], {"matched": checkpoints, "total": checkpoints})
        timing = report["timeline_policy"]
        expected = {"path": path, "sha256": hashlib.sha256(contents).hexdigest(), "passed": passed}
        if policy_commit is not None:
            expected["commit"] = policy_commit
            self.assertIn(f"Loaded the policy from Git commit `{policy_commit}`.", result.stdout)
        self.assertEqual({key: value for key, value in timing.items() if key != "checks"}, expected)
        checks = timing["checks"]
        passed_checks = sum(item["gate"]["passed"] for item in checks)
        verdict = "Passed" if passed else "Failed"
        self.assertIn("## Alert firing delay policy", result.stdout)
        self.assertIn(f"**{verdict}** ({passed_checks}/{len(checks)} checks)", result.stdout)
        self.assertEqual(result.stdout.count("### Prometheus alert firing timeline"), len(checks))

        root = ElementTree.parse(junit).getroot()
        failures = len(checks) - passed_checks
        self.assertEqual(root.get("tests"), str(checkpoints + len(checks)))
        self.assertEqual(root.get("failures"), str(failures))
        suite = root.findall("testsuite")[-1]
        self.assertEqual(suite.get("name"), "Alert firing delay")
        self.assertEqual(suite.get("tests"), str(len(checks)))
        self.assertEqual(suite.get("failures"), str(failures))
        cases = suite.findall("testcase")
        for case, item in zip(cases, checks, strict=True):
            self.assertEqual(case.get("classname"), item["fixture_path"])
            self.assertIn(ALERT, case.get("name", ""))
            self.assertEqual(case.find("failure") is None, item["gate"]["passed"])
        return report

    def test_ordered_fixture_checks_have_independent_delay_limits(self):
        path = "incident delay policy.json"
        bytes_before = policy_bytes(
            check(source=f"./{self.second}"),
            check(source=self.first, limit="239999ms"),
        )
        (self.workspace / path).write_bytes(bytes_before)
        outcome = self.compare(
            "fixture batch", (self.first, self.second), path, "--before", FAST, "--after", SLOW,
        )

        report = self.assert_policy(outcome, passed=False, path=path, contents=bytes_before, checkpoints=4)
        checks = report["timeline_policy"]["checks"]
        self.assertEqual([item["fixture_path"] for item in checks], [self.second, self.first])
        self.assertEqual([item["gate"]["passed"] for item in checks], [True, False])
        self.assertEqual([item["gate"]["max_delay_ms"] for item in checks], [240_000, 239_999])
        self.assertEqual([item["groups"][0]["first_firing_delta_ms"] for item in checks], [240_000, 240_000])
        self.assertEqual((self.workspace / path).read_bytes(), bytes_before)

    def test_each_bundle_check_reuses_its_own_archived_baseline(self):
        slow_archive = "cards/history.zip"
        fast_archive = "refunds/history.zip"
        for archive, rule in ((slow_archive, SLOW), (fast_archive, FAST)):
            result = self.cli(
                "bundle", self.config_path, "--matrix", DEMO / "incident.matrix.json",
                "--output", archive, "--rule-file", rule,
            )
            self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        path = "bundled alert policy.json"
        content = policy_bytes(check(source=fast_archive, limit="1m"), check(source=slow_archive, limit="1m"))
        (self.workspace / path).write_bytes(content)
        outcome = self.compare(
            "bundle batch", (slow_archive, fast_archive), path, "--after", SLOW, command="compare-bundle",
        )

        report = self.assert_policy(outcome, passed=False, path=path, contents=content, checkpoints=4)
        checks = report["timeline_policy"]["checks"]
        self.assertEqual([item["bundle"]["path"] for item in checks], [fast_archive, slow_archive])
        self.assertEqual([item["bundle"] for item in checks], list(reversed(report["bundles"])))
        self.assertEqual([item["baseline_source"] for item in checks], ["bundle", "bundle"])
        self.assertEqual([item["groups"][0]["first_firing_delta_ms"] for item in checks], [240_000, 0])
        self.assertEqual([item["gate"]["passed"] for item in checks], [False, True])

    @unittest.skipUnless(shutil.which("git"), "Git is required to pin policy")
    def test_fixture_ref_pins_policy_despite_a_more_permissive_working_policy(self):
        repo = self.workspace / "pinned policy repo"
        repo.mkdir()

        def git(*arguments):
            return subprocess.check_output(
                [
                    "git", "-C", repo, "-c", "user.name=Integration Test", "-c", "user.email=test@example.invalid",
                    "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false",
                    "-c", f"core.hooksPath={os.devnull}", *arguments,
                ],
                text=True, stderr=subprocess.PIPE, timeout=30,
            ).strip()

        path = "cards/firing [policy].json"
        alternate = "cards/policy-link.json"
        rule = "active rules.yml"
        git("init", "--quiet")
        (repo / self.first).parent.mkdir()
        shutil.copyfile(self.workspace / self.first, repo / self.first)
        content = policy_bytes(check(limit="1m"))
        (repo / path).write_bytes(content)
        (repo / alternate).symlink_to(Path(path).name)
        git("add", "--", ".")
        git("commit", "--quiet", "-m", "Record the trusted fixture and policy")
        capture = git("rev-parse", "HEAD")

        shutil.copyfile(FAST, repo / rule)
        git("add", "--", rule)
        git("commit", "--quiet", "-m", "Add the baseline alert")
        before = git("rev-parse", "HEAD")
        shutil.copyfile(SLOW, repo / rule)
        permissive = policy_bytes(check(limit="240s"))
        (repo / path).write_bytes(permissive)
        git("add", "--", rule, path)
        git("commit", "--quiet", "-m", "Slow the alert and loosen the policy")
        after = git("rev-parse", "HEAD")
        (repo / path).write_bytes(policy_bytes(check(limit="10m")))
        dirty = git("status", "--porcelain=v1")
        revisions = ("--before-ref", "HEAD^", "--after-ref", "HEAD", "--rule-file", rule)
        pinned = (*revisions, "--fixture-ref", "HEAD~2")

        outcome = self.compare("git pinned", (self.first,), path, *pinned, cwd=repo)

        report = self.assert_policy(
            outcome, passed=False, path=path, contents=content, checkpoints=2, policy_commit=capture,
        )
        self.assertEqual(report["commits"], {"before": before, "after": after})
        only, = report["timeline_policy"]["checks"]
        self.assertEqual(only["fixture_commit"], capture)
        self.assertEqual(only["gate"]["max_delay_ms"], 60_000)

        working = self.compare("git working policy", (self.first,), path, *revisions, cwd=repo)
        self.assert_policy(working, passed=True, path=path, contents=(repo / path).read_bytes(), checkpoints=2)
        self.assertEqual(git("rev-parse", "HEAD"), after)
        self.assertEqual(git("status", "--porcelain=v1"), dirty)

        stub, marker = self.promtool_stub("pinned symlink")
        outcome = self.compare("git symlink policy", (self.first,), alternate, *pinned, cwd=repo, promtool=stub)
        self.assert_preflight(outcome, marker, r"(?i)regular file")

    def promtool_stub(self, name):
        marker = self.workspace / f"{name}.ran-promtool"
        stub = self.workspace / f"{name}.promtool"
        stub.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        stub.chmod(0o700)
        return stub, marker

    def assert_preflight(self, outcome, marker, diagnostic):
        result, machine, junit = outcome
        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(result.stdout, "")
        self.assertRegex(result.stderr, diagnostic)
        for path in (marker, machine, junit):
            self.assertFalse(path.exists(), f"failed preflight should not create {path.name}")

    def test_rejects_invalid_or_over_budget_policy_without_starting_promtool(self):
        stub, marker = self.promtool_stub("invalid policy")
        single = (self.first,)
        batch = (self.first, self.second)
        invalid = (
            ("wrong version type", single, b'{"schema_version":true,"checks":[]}', r"(?i)schema.version"),
            ("unknown root key", single, b'{"schema_version":1,"checks":[],"surprise":1}', r"(?i)unknown|surprise"),
            ("empty checks", single, policy_bytes(), r"(?i)checks"),
            ("duplicate key", single, policy_bytes(check()).replace(b'"end": "10m"', b'"end":"9m","end":"10m"'),
             r"(?i)duplicate|key"),
            ("unknown check key", single, policy_bytes({**check(), "surprise": 1}), r"(?i)unknown|surprise"),
            ("missing max delay", single, policy_bytes({"alertname": ALERT, "end": "10m"}), r"(?i)max_delay"),
            ("invalid duration", single, policy_bytes(check(limit="later")), r"(?i)duration|delay"),
            ("unaligned end", single, policy_bytes(check(end="1s")), r"(?i)align|tick|evaluation"),
            ("missing source", batch, policy_bytes(check()), r"(?i)source"),
            ("unlisted source", batch, policy_bytes(check(source="other.test.yml")), r"(?i)source|fixture"),
            ("same resolved source and alert", batch, policy_bytes(check(source=self.first), check(source=f"./{self.first}")),
             r"(?i)duplicate|only once"),
            ("combined tick cap", batch,
             policy_bytes(check(source=self.first, end="180000s"), check(source=self.second, end="180000s")),
             r"(?i)10[,_ ]?000|limit|too many|exceed"),
        )
        for index, (name, sources, content, diagnostic) in enumerate(invalid):
            with self.subTest(case=name):
                path = f"invalid-{index}.policy.json"
                (self.workspace / path).write_bytes(content)
                outcome = self.compare(f"invalid-{index}", sources, path, "--before", FAST, "--after", SLOW, promtool=stub)
                self.assert_preflight(outcome, marker, diagnostic)

        path = "mixed flags.policy.json"
        (self.workspace / path).write_bytes(policy_bytes(check()))
        for suffix, extra in (("alert", ("--timeline-alertname", ALERT)), ("selection", ("--timeline-fixture", self.first))):
            with self.subTest(extra=extra):
                outcome = self.compare(
                    f"mixed {suffix}", single, path, "--before", FAST, "--after", SLOW, *extra, promtool=stub,
                )
                self.assert_preflight(outcome, marker, r"(?i)timeline.policy.*(?:mix|combine|exclusive|choose|cannot)")


if __name__ == "__main__":
    unittest.main()
