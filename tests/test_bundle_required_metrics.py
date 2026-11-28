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
MATRIX = "incident.matrix.json"
PAYMENT = "payment_http_requests_total"
CONTEXT = "capture:context_total"
REQUIRED = [PAYMENT, CONTEXT]


class BundleRequiredMetricsIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(executable).resolve() if executable else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        matrix = json.loads((DEMO / MATRIX).read_bytes())
        payment, = matrix["data"]["result"]
        for metric in (CONTEXT, f"{CONTEXT}_suffix"):
            matrix["data"]["result"].append({
                "metric": {"__name__": metric, "source": "capture"},
                "values": [[time, "1"] for time, _ in payment["values"]],
            })
        source = cls.workspace / "input.json"
        source.write_text(json.dumps(matrix), encoding="utf-8")
        cls.complete = "complete payment.zip"
        built = cls.cli("bundle", DEMO / "demo.json", "--matrix", source, "--output", cls.complete)
        if built.returncode:
            raise AssertionError(f"Could not create bundle:\n{built.stdout}{built.stderr}")

        # Keep the compiled fixture and archived report intact while putting the exact metric outside the raw window.
        outside = json.loads(source.read_bytes())
        context = next(series for series in outside["data"]["result"] if series["metric"]["__name__"] == CONTEXT)
        context["values"] = [[payment["values"][0][0] - 1, "1"]]
        cls.missing = cls.rewrite("missing context.zip", {MATRIX: json.dumps(outside).encode()})

        del payment["values"][3]
        cls.sparse = cls.rewrite("sparse payment.zip", {MATRIX: json.dumps(matrix).encode()})

    @classmethod
    def cli(cls, *arguments):
        return subprocess.run(
            [sys.executable, CLI, *arguments], cwd=cls.workspace, capture_output=True, text=True, timeout=30,
        )

    @classmethod
    def rewrite(cls, name, updates, *, rehash=True):
        with ZipFile(cls.workspace / cls.complete) as source:
            members = {path: source.read(path) for path in source.namelist()}
        members.update(updates)
        if rehash:
            manifest = json.loads(members["manifest.json"])
            for path, content in updates.items():
                manifest["files"][path] = hashlib.sha256(content).hexdigest()
            members["manifest.json"] = json.dumps(manifest).encode()
        with ZipFile(cls.workspace / name, "w") as archive:
            for path, content in members.items():
                archive.writestr(path, content)
        return name

    def verify(self, archive, *names, extra=(), output_format="json"):
        options = [f"--require-metric={name}" for name in names]
        return self.cli("verify-bundle", archive, "--format", output_format, *options, *extra)

    def compare(self, name, archives, *metrics, extra=(), rules=("--after", DEMO / "after.rules.yml"), executable=None):
        executable = executable or self.promtool
        if executable is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        machine = self.workspace / f"{name}.json"
        junit = self.workspace / f"{name}.xml"
        options = [f"--bundle-require-metric={metric}" for metric in metrics]
        result = self.cli(
            "compare-bundle", *archives, *rules, "--promtool", executable,
            "--json-report", machine, "--junit-report", junit, *options, *extra,
        )
        return result, machine, junit

    def assert_exit(self, result, expected):
        self.assertEqual(result.returncode, expected, f"{result.stdout}\n{result.stderr}")

    def assert_metrics(self, coverage, missing):
        self.assertEqual(coverage["required_metrics"], {
            "names": REQUIRED, "missing": missing, "passed": not missing,
        })

    def test_verify_required_metrics_from_raw_window_and_preserve_ungated_output(self):
        ungated = self.verify(self.missing)
        self.assert_exit(ungated, 0)
        self.assertNotIn("coverage", json.loads(ungated.stdout))
        for name, missing in ((self.complete, []), (self.missing, [CONTEXT])):
            with self.subTest(bundle=name):
                report = self.verify(name, *REQUIRED)
                self.assert_exit(report, int(bool(missing)))
                checked = json.loads(report.stdout)
                self.assertIsNone(checked["coverage"]["gate"])
                self.assert_metrics(checked["coverage"], missing)
                self.assertEqual(checked["verified_files"], json.loads(ungated.stdout)["verified_files"])

        with ZipFile(self.workspace / self.missing) as bundle:
            fixture = json.loads(bundle.read("incident.test.yml"))
            archived = json.loads(bundle.read("coverage.json"))
            for series in (fixture["tests"][0]["input_series"], archived["series"]):
                self.assertTrue(any(item["series"].startswith(CONTEXT + "{") for item in series))
        markdown = self.verify(self.missing, *REQUIRED, output_format="markdown")
        self.assert_exit(markdown, 1)
        self.assertIn(CONTEXT, unescape(markdown.stdout))

        empty_matrix = b'{"status":"success","data":{"resultType":"matrix","result":[]}}'
        empty = self.rewrite("no observed metrics.zip", {MATRIX: empty_matrix})
        no_samples = self.verify(empty, *REQUIRED)
        self.assert_exit(no_samples, 1)
        self.assert_metrics(json.loads(no_samples.stdout)["coverage"], REQUIRED)

        gap_only_failure = self.verify(self.sparse, *REQUIRED, extra=("--max-gap", "30s"))
        self.assert_exit(gap_only_failure, 1)
        coverage = json.loads(gap_only_failure.stdout)["coverage"]
        self.assert_metrics(coverage, [])
        self.assertEqual(coverage["gate"], {"max_gap_ms": 30_000, "passed": False})
        metric_only_failure = self.verify(self.missing, *REQUIRED, extra=("--max-gap", "30s"))
        self.assert_exit(metric_only_failure, 1)
        coverage = json.loads(metric_only_failure.stdout)["coverage"]
        self.assert_metrics(coverage, [CONTEXT])
        self.assertEqual(coverage["gate"], {"max_gap_ms": 30_000, "passed": True})

    def test_required_metrics_only_is_optional_and_publishes_each_bundle_result(self):
        archives = (self.complete, self.missing)
        plain, plain_report, plain_junit = self.compare("ungated replay", archives)
        self.assert_exit(plain, 0)
        self.assertNotIn("bundle_coverage", json.loads(plain_report.read_bytes()))
        self.assertIsNone(ElementTree.parse(plain_junit).find("testsuite[@name='Bundle sample coverage']"))

        passed, passing_report, _ = self.compare("all metrics present", (self.complete,), *REQUIRED)
        self.assert_exit(passed, 0)
        self.assertIs(json.loads(passing_report.read_bytes())["bundle_coverage"]["passed"], True)

        result, machine, junit = self.compare("required metrics", archives, *REQUIRED)
        self.assert_exit(result, 1)
        self.assertIn(CONTEXT, unescape(result.stdout))
        report = json.loads(machine.read_bytes())
        self.assertEqual(report["gate"], {"mode": "strict", "passed": True})
        coverage = report["bundle_coverage"]
        self.assertNotIn("max_gap_ms", coverage)
        self.assertEqual(coverage["required_metrics"], REQUIRED)
        self.assertIs(coverage["passed"], False)
        self.assertEqual([entry["path"] for entry in coverage["checks"]], list(archives))
        for entry, missing in zip(coverage["checks"], ([], [CONTEXT]), strict=True):
            self.assertIsNone(entry["coverage"]["gate"])
            self.assert_metrics(entry["coverage"], missing)

        root = ElementTree.parse(junit).getroot()
        self.assertEqual((root.get("tests"), root.get("failures")), ("6", "1"))
        suite = root.find("testsuite[@name='Bundle sample coverage']")
        self.assertEqual((suite.get("tests"), suite.get("failures")), ("2", "1"))
        self.assertEqual([case.get("classname") for case in suite], list(archives))
        failure, = suite.findall("testcase/failure")
        self.assertEqual(failure.get("type"), "required-metrics")
        self.assertIn(CONTEXT, failure.text)

    def test_gap_required_metrics_and_timing_remain_independent(self):
        archives = (self.missing, self.sparse)
        result, machine, junit = self.compare("mixed criteria", archives, *REQUIRED, extra=(
            "--bundle-max-gap", "30s", "--timeline-alertname", "PaymentErrorsHigh", "--timeline-end", "10m",
            "--timeline-max-delay", "0s", "--timeline-bundle", self.sparse,
        ))
        self.assert_exit(result, 1)
        report = json.loads(machine.read_bytes())
        self.assertIs(report["gate"]["passed"], True)
        self.assertIs(report["timeline"]["gate"]["passed"], True)
        coverage = report["bundle_coverage"]
        self.assertEqual(coverage["max_gap_ms"], 30_000)
        self.assertEqual(coverage["required_metrics"], REQUIRED)
        self.assertIs(coverage["passed"], False)
        self.assertEqual([entry["path"] for entry in coverage["checks"]], list(archives))
        missing, sparse = (entry["coverage"] for entry in coverage["checks"])
        self.assertEqual(missing["gate"], {"max_gap_ms": 30_000, "passed": True})
        self.assertEqual(sparse["gate"], {"max_gap_ms": 30_000, "passed": False})
        self.assert_metrics(missing, [CONTEXT])
        self.assert_metrics(sparse, [])

        root = ElementTree.parse(junit).getroot()
        self.assertEqual((root.get("tests"), root.get("failures")), ("9", "2"))
        suite = root.find("testsuite[@name='Bundle sample coverage']")
        self.assertEqual((suite.get("tests"), suite.get("failures")), ("4", "2"))
        self.assertCountEqual([case.get("classname") for case in suite], [self.missing] * 2 + [self.sparse] * 2)
        failures = {case.get("classname"): case.find("failure") for case in suite if case.find("failure") is not None}
        self.assertEqual({name: failure.get("type") for name, failure in failures.items()}, {
            self.missing: "required-metrics", self.sparse: "max-gap",
        })
        self.assertIn(CONTEXT, failures[self.missing].text)

    def test_preflight_rejects_invalid_names_and_unverified_raw_bytes(self):
        marker = self.workspace / "promtool started"
        stub = self.workspace / "promtool stub"
        stub.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        stub.chmod(0o700)
        with ZipFile(self.workspace / self.complete) as source:
            wrong_hash = self.rewrite("wrong raw digest.zip", {MATRIX: source.read(MATRIX) + b"\n"}, rehash=False)
        cases = (
            (self.complete, f'{PAYMENT}{{code="500"}}', r"(?i)metric|name"),
            (wrong_hash, CONTEXT, r"(?i)sha-?256|hash|digest"),
        )
        for index, (archive, name, diagnostic) in enumerate(cases):
            with self.subTest(archive=archive):
                verify = self.verify(archive, name)
                compare, machine, junit = self.compare(f"preflight {index}", (archive,), name, executable=stub)
                for result in (verify, compare):
                    self.assert_exit(result, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertRegex(result.stderr, diagnostic)
                for path in (machine, junit, marker):
                    self.assertFalse(path.exists())

    @unittest.skipUnless(shutil.which("git"), "Git is required for bundle ref comparison")
    def test_required_metric_check_uses_bundle_ref(self):
        repo = self.workspace / "pinned required metrics"
        repo.mkdir()

        def git(*arguments):
            return subprocess.check_output(
                [
                    "git", "-C", repo, "-c", "user.name=Integration Test", "-c", "user.email=test@example.invalid",
                    "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", "-c", f"core.hooksPath={os.devnull}", *arguments,
                ], stderr=subprocess.PIPE, text=True, timeout=30,
            ).strip()

        git("init", "--quiet")
        archive = "pinned payment.zip"
        candidate = "candidate.yml"
        shutil.copyfile(self.workspace / self.missing, repo / archive)
        shutil.copyfile(DEMO / "after.rules.yml", repo / candidate)
        git("add", "--", archive, candidate)
        git("commit", "--quiet", "-m", "Store incident with one missing metric")
        revision = git("rev-parse", "HEAD")
        shutil.copyfile(self.workspace / self.complete, repo / archive)

        result, machine, _ = self.compare("pinned replay", (archive,), *REQUIRED, rules=(
            "--repo", repo, "--bundle-ref", revision, "--after-ref", revision, "--rule-file", candidate,
        ))
        self.assert_exit(result, 1)
        report = json.loads(machine.read_bytes())
        self.assertEqual(report["commits"], {"before": revision, "after": revision})
        self.assertIs(report["gate"]["passed"], True)
        check, = report["bundle_coverage"]["checks"]
        self.assertEqual(check["path"], archive)
        self.assert_metrics(check["coverage"], [CONTEXT])


if __name__ == "__main__":
    unittest.main()
