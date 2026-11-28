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
PAYMENT = "payment_http_requests_total"
CONTEXT = "capture:context_total"


def policy_bytes(*checks):
    return (json.dumps({"schema_version": 1, "checks": checks}, indent=2) + "\n").encode("utf-8")


class BundleCoverageFileIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(executable).resolve() if executable else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        original = (DEMO / "incident.matrix.json").read_bytes()
        dense = json.loads(original)
        observed = dense["data"]["result"]
        observed.append({
            "metric": {"__name__": CONTEXT, "source": "capture"},
            "values": [[timestamp, "1"] for timestamp, _ in observed[0]["values"]],
        })
        sparse = json.loads(original)
        del sparse["data"]["result"][0]["values"][3]
        cls.dense = "dense [capture].zip"
        cls.sparse = "sparse & selected.zip"
        cls.metric_only = "metrics only.zip"
        for name, matrix in ((cls.dense, dense), (cls.sparse, sparse)):
            source = cls.workspace / f"{name}.matrix.json"
            source.write_text(json.dumps(matrix), encoding="utf-8")
            outcome = cls.cli("bundle", DEMO / "demo.json", "--matrix", source, "--rule-file", SLOW, "--output", name)
            if outcome.returncode:
                raise AssertionError(f"Could not create {name}:\n{outcome.stdout}{outcome.stderr}")
        shutil.copyfile(cls.workspace / cls.sparse, cls.workspace / cls.metric_only)

    @classmethod
    def cli(cls, *arguments, cwd=None):
        return subprocess.run(
            [sys.executable, CLI, *arguments], cwd=cwd or cls.workspace,
            capture_output=True, text=True, timeout=30,
        )

    def compare(self, name, archives, policy, *options, rules=("--after", FAST), executable=None, cwd=None):
        if executable is None and self.promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        machine = self.workspace / f"{name}.report.json"
        junit = self.workspace / f"{name}.report.xml"
        result = self.cli(
            "compare-bundle", *archives, *rules, "--bundle-coverage-policy", policy,
            "--promtool", executable or self.promtool, "--json-report", machine, "--junit-report", junit, *options,
            cwd=cwd,
        )
        return result, machine, junit

    def write_policy(self, name, content):
        (self.workspace / name).write_bytes(content)
        return name

    def assert_exit(self, result, expected):
        self.assertEqual(result.returncode, expected, f"{result.stdout}\n{result.stderr}")

    def assert_policy_report(self, outcome, exit_code, path, content, passed, archives, *, commit=None):
        result, machine, junit = outcome
        self.assert_exit(result, exit_code)
        self.assertIn("Bundle sample coverage", result.stdout)
        report = json.loads(machine.read_bytes())
        self.assertEqual(report["gate"], {"mode": "strict", "passed": True})
        coverage = report["bundle_coverage"]
        self.assertEqual(set(coverage), {"policy", "passed", "checks"})
        self.assertEqual(coverage["passed"], passed)
        expected_origin = {"path": path, "sha256": hashlib.sha256(content).hexdigest()}
        if commit is not None:
            expected_origin["commit"] = commit
        self.assertEqual(coverage["policy"], expected_origin)
        self.assertEqual([check["path"] for check in coverage["checks"]], list(archives))
        root = ElementTree.parse(junit).getroot()
        suite = root.find("testsuite[@name='Bundle sample coverage']")
        self.assertIsNotNone(suite)
        return report, root, suite

    def test_batch_maps_distinct_policies_by_path_and_composes_with_timeline(self):
        archives = (self.sparse, self.dense, self.metric_only)
        content = policy_bytes(
            {"source": self.metric_only, "required_metrics": [CONTEXT]},
            {"source": self.dense, "max_gap": "30s", "required_metrics": [CONTEXT, PAYMENT, CONTEXT]},
            {"source": self.sparse, "max_gap": "59999ms", "required_metrics": [PAYMENT]},
        )
        policy = self.write_policy("per-incident policy.json", content)
        result = self.compare(
            "batch", archives, policy, "--timeline-alertname", ALERT, "--timeline-end", "10m",
            "--timeline-max-delay", "0s", "--timeline-bundle", self.dense,
        )

        report, root, suite = self.assert_policy_report(result, 1, policy, content, False, archives)
        self.assertEqual(report["summary"]["after"], {"matched": 6, "total": 6})
        self.assertTrue(report["timeline"]["gate"]["passed"])
        sparse, dense, metrics_only = [check["coverage"] for check in report["bundle_coverage"]["checks"]]
        self.assertEqual(sparse["gate"], {"max_gap_ms": 59_999, "passed": False})
        self.assertEqual(sparse["required_metrics"], {"names": [PAYMENT], "missing": [], "passed": True})
        self.assertEqual(dense["gate"], {"max_gap_ms": 30_000, "passed": True})
        self.assertEqual(dense["required_metrics"], {"names": [CONTEXT, PAYMENT], "missing": [], "passed": True})
        self.assertIsNone(metrics_only["gate"])
        self.assertEqual(metrics_only["required_metrics"], {"names": [CONTEXT], "missing": [CONTEXT], "passed": False})

        self.assertEqual((root.get("tests"), root.get("failures")), ("12", "2"))
        self.assertEqual((suite.get("tests"), suite.get("failures")), ("5", "2"))
        self.assertCountEqual([case.get("classname") for case in suite], [self.sparse] * 2 + [self.dense] * 2 + [self.metric_only])
        failures = {case.get("classname"): case.find("failure") for case in suite if case.find("failure") is not None}
        self.assertEqual({path: failure.get("type") for path, failure in failures.items()}, {
            self.sparse: "max-gap", self.metric_only: "required-metrics",
        })
        self.assertIn(CONTEXT, failures[self.metric_only].text)

    def test_single_bundle_check_may_omit_source_and_preserves_inspect_shape(self):
        content = policy_bytes({"max_gap": "60s"})
        path = self.write_policy("single policy.json", content)
        outcome = self.compare("single", (self.sparse,), path)

        report, root, suite = self.assert_policy_report(outcome, 0, path, content, True, (self.sparse,))
        coverage = report["bundle_coverage"]["checks"][0]["coverage"]
        verified = self.cli("verify-bundle", self.sparse, "--format", "json", "--max-gap", "60s")
        self.assert_exit(verified, 0)
        self.assertEqual(coverage, json.loads(verified.stdout)["coverage"])
        self.assertNotIn("required_metrics", coverage)
        self.assertEqual((root.get("tests"), root.get("failures")), ("3", "0"))
        case, = suite.findall("testcase")
        self.assertEqual(case.get("classname"), self.sparse)
        self.assertIsNone(case.find("failure"))

    def test_malformed_policy_and_global_coverage_conflicts_stop_before_replay(self):
        marker = self.workspace / "policy preflight ran promtool"
        stub = self.workspace / "policy preflight stub"
        stub.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        stub.chmod(0o700)
        single = (self.dense,)
        batch = (self.sparse, self.dense)
        valid = {"source": self.dense, "max_gap": "30s"}
        invalid = (
            ("wrong version", single, b'{"schema_version":true,"checks":[]}', r"(?i)schema.version"),
            ("unknown root field", single, b'{"schema_version":1,"checks":[],"fallback":1}', r"(?i)unknown|fallback"),
            ("no checks", single, policy_bytes(), r"(?i)checks"),
            ("duplicate member", single, b'{"schema_version":1,"checks":[{"max_gap":"1s","max_gap":"2s"}]}',
             r"(?i)duplicate"),
            ("unknown check field", single, policy_bytes({**valid, "optional": True}), r"(?i)unknown|optional"),
            ("missing criteria", single, policy_bytes({"source": self.dense}), r"(?i)max.gap|required.metrics|criterion"),
            ("missing source in batch", batch, policy_bytes({"max_gap": "30s"}, valid), r"(?i)source"),
            ("incomplete list", batch, policy_bytes(valid), r"(?i)one check|missing|sparse"),
            ("duplicate source", batch, policy_bytes(valid, valid), r"(?i)duplicate|one check"),
            ("exact source required", single, policy_bytes({**valid, "source": f"./{self.dense}"}), r"(?i)source|supplied"),
            ("unlisted extra source", single, policy_bytes(valid, {**valid, "source": self.sparse}), r"(?i)source|supplied|check"),
            ("null source", single, policy_bytes({**valid, "source": None}), r"(?i)source"),
            ("numeric gap", single, policy_bytes({**valid, "max_gap": 30}), r"(?i)max.gap|duration"),
            ("zero gap", single, policy_bytes({**valid, "max_gap": "0s"}), r"(?i)max.gap|positive"),
            ("null gap", single, policy_bytes({"max_gap": None, "required_metrics": [CONTEXT]}), r"(?i)max.gap|duration|positive"),
            ("empty metrics", single, policy_bytes({**valid, "required_metrics": []}), r"(?i)required.metrics|non.empty"),
            ("invalid metric list", single, policy_bytes({"required_metrics": PAYMENT}), r"(?i)required.metrics|array"),
            ("invalid metric name", single, policy_bytes({"required_metrics": ["not a metric"]}), r"(?i)required.metrics|metric name"),
        )
        for index, (name, archives, content, diagnostic) in enumerate(invalid):
            with self.subTest(case=name):
                policy = self.write_policy(f"invalid-{index}.json", content)
                outcome = self.compare(f"invalid-{index}", archives, policy, executable=stub)
                self.assert_no_reports(outcome, marker, diagnostic)

        policy = self.write_policy("exclusive policy.json", policy_bytes(valid))
        for flag, value in (("--bundle-max-gap", "1m"), ("--bundle-require-metric", PAYMENT)):
            with self.subTest(flag=flag):
                outcome = self.compare(f"exclusive-{flag}", single, policy, flag, value, executable=stub)
                self.assert_no_reports(outcome, marker, r"(?i)cannot.*combine|exclusive|choose|conflict")

    def assert_no_reports(self, outcome, marker, diagnostic):
        result, machine, junit = outcome
        self.assert_exit(result, 2)
        self.assertEqual(result.stdout, "")
        self.assertRegex(result.stderr, diagnostic)
        for path in (machine, junit, marker):
            self.assertFalse(path.exists(), f"failed preflight must not create {path.name}")

    @unittest.skipUnless(shutil.which("git"), "Git is required to pin coverage policy")
    def test_git_bundle_ref_pins_the_policy_despite_permissive_working_input(self):
        repo = self.workspace / "coverage repo"
        repo.mkdir()

        def git(*arguments):
            return subprocess.check_output(
                [
                    "git", "-C", repo, "-c", "user.name=Integration Test", "-c", "user.email=test@example.invalid",
                    "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", "-c", f"core.hooksPath={os.devnull}",
                    *arguments,
                ],
                text=True, stderr=subprocess.PIPE, timeout=30,
            ).strip()

        git("init", "--quiet")
        (repo / "captures").mkdir()
        (repo / "policies").mkdir()
        archives = (f"captures/{self.sparse}", f"captures/{self.dense}")
        for destination, source in zip(archives, (self.sparse, self.dense), strict=True):
            shutil.copyfile(self.workspace / source, repo / destination)
        path = "policies/coverage [policy].json"
        dense_check = {"source": archives[1], "required_metrics": [CONTEXT]}
        pinned = policy_bytes(dense_check, {"source": archives[0], "max_gap": "30s"})
        (repo / path).write_bytes(pinned)
        git("add", "--", ".")
        git("commit", "--quiet", "-m", "Capture bundles and original coverage policy")
        before = git("rev-parse", "HEAD")

        proposed = "proposed [rule].yml"
        shutil.copyfile(FAST, repo / proposed)
        (repo / path).write_bytes(policy_bytes(dense_check, {"source": archives[0], "max_gap": "60s"}))
        (repo / archives[0]).write_bytes(b"invalid newer archive")
        git("add", "--", ".")
        git("commit", "--quiet", "-m", "Loosen the candidate policy and improve the alert")
        after = git("rev-parse", "HEAD")
        (repo / path).write_bytes(policy_bytes(dense_check, {"source": archives[0], "max_gap": "10m"}))
        (repo / archives[1]).unlink()
        dirty = git("status", "--porcelain=v1")

        result = self.compare(
            "git pinned", archives, path,
            rules=("--bundle-ref", "HEAD^", "--after-ref", "HEAD", "--rule-file", proposed), cwd=repo,
        )

        report, _, _ = self.assert_policy_report(result, 1, path, pinned, False, archives, commit=before)
        self.assertEqual(report["commits"], {"before": before, "after": after})
        sparse, dense = [item["coverage"] for item in report["bundle_coverage"]["checks"]]
        self.assertEqual(sparse["gate"], {"max_gap_ms": 30_000, "passed": False})
        self.assertTrue(dense["required_metrics"]["passed"])
        self.assertEqual(git("rev-parse", "HEAD"), after)
        self.assertEqual(git("status", "--porcelain=v1"), dirty)


if __name__ == "__main__":
    unittest.main()
