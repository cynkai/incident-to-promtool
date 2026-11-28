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
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
FAST = DEMO / "after.rules.yml"
SLOW = DEMO / "before.rules.yml"
CONFIG = "incident.json"
MATRIX = "incident.matrix.json"
ALERT = "PaymentErrorsHigh"


class BundleCoveragePolicyIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        cls.promtool = Path(executable).resolve() if executable else None
        workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        cls.workspace = Path(workspace.name)
        config_path = cls.workspace / "late checkpoint.json"
        config = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        config["expectations"][-1]["at"] = "10m"
        config_path.write_text(json.dumps(config), encoding="utf-8")

        dense_matrix = DEMO / MATRIX
        sparse_matrix = cls.workspace / "missing one sample.json"
        matrix = json.loads(dense_matrix.read_text(encoding="utf-8"))
        samples = matrix["data"]["result"][0]["values"]
        del samples[3]
        sparse_matrix.write_text(json.dumps(matrix), encoding="utf-8")
        cls.dense = "dense [capture].zip"
        cls.sparse = "sparse & ungated.zip"
        inputs = (
            (cls.dense, dense_matrix, ("--max-gap", "1m")),
            (cls.sparse, sparse_matrix, ()),
        )
        for name, source, options in inputs:
            result = cls.cli(
                "bundle", config_path, "--matrix", source, "--rule-file", FAST, "--output", name, *options,
            )
            if result.returncode:
                raise AssertionError(f"Could not create {name}:\n{result.stdout}{result.stderr}")

    @classmethod
    def cli(cls, *arguments):
        return subprocess.run(
            [sys.executable, CLI, *arguments], cwd=cls.workspace, capture_output=True, text=True, timeout=30,
        )

    def verify(self, archive, max_gap=None, *, output_format="json"):
        extra = (f"--max-gap={max_gap}",) if max_gap is not None else ()
        return self.cli("verify-bundle", archive, "--format", output_format, *extra)

    def compare(self, name, archives, *options, max_gap=None, rules=("--after", SLOW), promtool=None):
        if promtool is None and self.promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        report = self.workspace / f"{name}.report.json"
        junit = self.workspace / f"{name}.report.xml"
        extra = (f"--bundle-max-gap={max_gap}",) if max_gap is not None else ()
        result = self.cli(
            "compare-bundle", *archives, *rules, "--promtool", promtool or self.promtool,
            "--json-report", report, "--junit-report", junit, *extra, *options,
        )
        return result, report, junit

    def rewrite(self, name, updates, *, rehash=True, legacy=False):
        with ZipFile(self.workspace / self.dense) as source:
            members = {path: source.read(path) for path in source.namelist()}
        members.update(updates)
        if legacy:
            members.pop("manifest.json")
            capture = json.loads(members["capture.json"])
            del capture["bundle_manifest_version"]
            del capture["coverage_gate"]
            capture["generation_options"] = []
            members["capture.json"] = json.dumps(capture).encode()
        elif rehash:
            manifest = json.loads(members["manifest.json"])
            for path, content in updates.items():
                manifest["files"][path] = hashlib.sha256(content).hexdigest()
            members["manifest.json"] = json.dumps(manifest).encode()
        with ZipFile(self.workspace / name, "w") as archive:
            for path, content in members.items():
                archive.writestr(path, content)
        return name

    def assert_exit(self, result, expected):
        self.assertEqual(result.returncode, expected, f"{result.stdout}\n{result.stderr}")

    def assert_operational_error(self, result, diagnostic):
        self.assert_exit(result, 2)
        self.assertEqual(result.stdout, "")
        self.assertRegex(result.stderr, diagnostic)

    def assert_verify_coverage(self, result, exit_code, max_gap_ms, sample_count, gap_ms):
        self.assert_exit(result, exit_code)
        report = json.loads(result.stdout)
        coverage = report["coverage"]
        self.assertEqual(coverage["gate"], {"max_gap_ms": max_gap_ms, "passed": exit_code == 0})
        self.assertEqual(coverage["sample_count"], sample_count)
        if sample_count:
            series, = coverage["series"]
            self.assertEqual(series["max_sample_gap"]["duration_ms"], gap_ms)
            self.assertIs(series["gap_exceeded"], exit_code != 0)
        else:
            self.assertEqual(coverage["series_count"], 0)
            self.assertEqual(coverage["series"], [])
        return report

    def assert_compare_coverage(self, outcome, exit_code, limit, checks, *, tests, failures, checkpoint_passed=True):
        result, machine, junit = outcome
        self.assert_exit(result, exit_code)
        self.assertIn("Bundle sample coverage", result.stdout)
        report = json.loads(machine.read_bytes())
        coverage = report["bundle_coverage"]
        self.assertEqual(report["gate"], {"mode": "strict", "passed": checkpoint_passed})
        self.assertEqual(coverage["max_gap_ms"], limit)
        self.assertIs(coverage["passed"], all(passed for _, passed in checks))
        self.assertEqual([
            (check["path"], check["coverage"]["gate"]["passed"]) for check in coverage["checks"]
        ], checks)
        self.assertTrue(all(check["coverage"]["gate"]["max_gap_ms"] == limit for check in coverage["checks"]))

        root = ElementTree.parse(junit).getroot()
        self.assertEqual(root.get("tests"), str(tests))
        self.assertEqual(root.get("failures"), str(failures))
        suite, = [item for item in root.findall("testsuite") if item.get("name") == "Bundle sample coverage"]
        cases = suite.findall("testcase")
        self.assertEqual([case.get("classname") for case in cases], [path for path, _ in checks])
        self.assertEqual(suite.get("tests"), str(len(checks)))
        self.assertEqual(suite.get("failures"), str(sum(not passed for _, passed in checks)))
        for case, (_, passed) in zip(cases, checks, strict=True):
            failure = case.find("failure")
            if passed:
                self.assertIsNone(failure)
            else:
                self.assertIsNotNone(failure)
                self.assertEqual(failure.get("type"), "max-gap")
                self.assertRegex(failure.text, r"(?i)largest gap|no .*sample")
        return report

    def test_verify_reports_exact_limit_on_preexisting_bundles_and_matches_inspect(self):
        cases = (
            (self.dense, "30s", 30_000, 21, 30_000),
            (self.sparse, "60s", 60_000, 20, 60_000),
        )
        for archive, limit, limit_ms, samples, gap in cases:
            with self.subTest(archive=archive):
                ungated = self.verify(archive)
                self.assert_exit(ungated, 0)
                passed = self.assert_verify_coverage(self.verify(archive, limit), 0, limit_ms, samples, gap)
                failed = self.assert_verify_coverage(
                    self.verify(archive, f"{limit_ms - 1}ms"), 1, limit_ms - 1, samples, gap,
                )
                self.assertEqual({key: value for key, value in passed.items() if key != "coverage"}, json.loads(ungated.stdout))
                self.assertEqual(failed["verified_files"], passed["verified_files"])

                unpacked = self.workspace / Path(archive).stem
                with ZipFile(self.workspace / archive) as bundle:
                    bundle.extract(CONFIG, unpacked)
                    bundle.extract(MATRIX, unpacked)
                inspect = self.cli("inspect", unpacked / CONFIG, "--matrix", unpacked / MATRIX, "--format", "json", "--max-gap", limit)
                self.assert_exit(inspect, 0)
                self.assertEqual(passed["coverage"], json.loads(inspect.stdout))

        markdown = self.verify(self.dense, "29999ms", output_format="markdown")
        self.assert_exit(markdown, 1)
        self.assertRegex(markdown.stdout, r"(?i)coverage|gap")
        self.assertIn("Failed", markdown.stdout)

    def test_bundle_batch_coverage_and_first_firing_gates_have_independent_results(self):
        archives = (self.sparse, self.dense)
        cases = (
            ("coverage only", "30s", 30_000, "240s", False, True, 1),
            ("timing only", "1m", 60_000, "0s", True, False, 1),
            ("both pass", "1m", 60_000, "240s", True, True, 0),
        )
        for name, threshold, threshold_ms, delay, sparse_passed, timing_passed, exit_code in cases:
            with self.subTest(case=name):
                result = self.compare(
                    name, archives, "--timeline-bundle", self.dense, "--timeline-alertname", ALERT,
                    "--timeline-end", "10m", "--timeline-max-delay", delay, max_gap=threshold,
                )

                checks = [(self.sparse, sparse_passed), (self.dense, True)]
                report = self.assert_compare_coverage(result, exit_code, threshold_ms, checks, tests=7, failures=exit_code)
                self.assertEqual(report["summary"]["after"], {"matched": 4, "total": 4})
                self.assertIs(report["timeline"]["gate"]["passed"], timing_passed)
                self.assertEqual([item["path"] for item in report["bundles"]], list(archives))

        unrelated = self.workspace / "replacement alert.yml"
        unrelated.write_text("groups:\n- name: other\n  rules:\n  - alert: Other\n    expr: vector(1)\n", encoding="utf-8")
        checkpoint_failure = self.compare("checkpoint only", archives, max_gap="1m", rules=("--after", unrelated))
        report = self.assert_compare_coverage(
            checkpoint_failure, 1, 60_000, [(self.sparse, True), (self.dense, True)],
            tests=6, failures=2, checkpoint_passed=False,
        )
        self.assertEqual(report["summary"]["after"], {"matched": 2, "total": 4})

        result, machine, junit = self.compare("no coverage gate", archives)
        self.assert_exit(result, 0)
        self.assertNotIn("bundle_coverage", json.loads(machine.read_bytes()))
        self.assertNotIn("Bundle sample coverage", result.stdout)
        self.assertEqual(ElementTree.parse(junit).getroot().get("tests"), "4")

    def test_recompute_ignores_claimed_coverage_and_empty_evidence_fails(self):
        with ZipFile(self.workspace / self.dense) as source:
            forged = json.loads(source.read("coverage.json"))
        forged["gate"] = {"max_gap_ms": 20_000, "passed": True}
        forged["series"][0]["max_sample_gap"]["duration_ms"] = 1
        archive = self.rewrite("claims it is healthy.zip", {"coverage.json": json.dumps(forged).encode()})
        self.assert_verify_coverage(self.verify(archive, "20s"), 1, 20_000, 21, 30_000)
        self.assert_compare_coverage(
            self.compare("forged coverage", (archive,), max_gap="20s"), 1, 20_000, [(archive, False)], tests=3, failures=1,
        )

        empty_capture = b'{"status":"success","data":{"resultType":"matrix","result":[]}}'
        empty = self.rewrite("empty evidence.zip", {MATRIX: empty_capture})
        self.assert_verify_coverage(self.verify(empty, "10m"), 1, 600_000, 0, None)
        report = self.assert_compare_coverage(
            self.compare("empty coverage", (empty,), max_gap="10m"), 1, 600_000, [(empty, False)], tests=3, failures=1,
        )
        self.assertEqual(report["bundle_coverage"]["checks"][0]["coverage"]["series"], [])

    def promtool_stub(self):
        marker = self.workspace / "coverage preflight ran promtool"
        stub = self.workspace / "coverage preflight stub"
        stub.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
        stub.chmod(0o700)
        return stub, marker

    def assert_preflight(self, outcome, marker, diagnostic):
        result, machine, junit = outcome
        self.assert_operational_error(result, diagnostic)
        for path in (machine, junit, marker):
            self.assertFalse(path.exists(), f"failed preflight must not create {path.name}")

    def test_coverage_preflight_requires_verified_parseable_raw_payloads(self):
        with ZipFile(self.workspace / self.dense) as source:
            config = source.read(CONFIG)
            raw = source.read(MATRIX)
        oversized_timestamp = (
            b'{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"extreme"},'
            b'"values":[[1e9999999999999999999999999999999,"1"]]}]}}'
        )
        overflowing_timestamp = oversized_timestamp.replace(b"1e9999999999999999999999999999999", b"1e999999")
        invalid = (
            (self.rewrite("tampered configuration.zip", {CONFIG: config + b"\n"}, rehash=False), r"(?i)sha-?256|hash|digest"),
            (self.rewrite("tampered matrix.zip", {MATRIX: raw + b"\n"}, rehash=False), r"(?i)sha-?256|hash|digest"),
            (self.rewrite("malformed configuration.zip", {CONFIG: b"{unfinished"}), r"(?i)json|expecting|config"),
            (self.rewrite("malformed matrix.zip", {MATRIX: b"{unfinished"}), r"(?i)json|expecting|matrix"),
            (self.rewrite("oversized timestamp.zip", {MATRIX: oversized_timestamp}), r"(?i)decimal|matrix|number|conversion"),
            (self.rewrite("overflowing timestamp.zip", {MATRIX: overflowing_timestamp}),
             r"(?i)invalid raw capture|overflow"),
            (self.rewrite("wrong result type.zip", {MATRIX: b'{"status":"success","data":{"resultType":"matrix","result":{}}}'}),
             r"(?i)matrix result|array"),
            (self.rewrite("old manifestless bundle.zip", {}, legacy=True), r"(?i)manifest"),
        )
        stub, marker = self.promtool_stub()
        for archive, diagnostic in invalid:
            with self.subTest(archive=archive):
                self.assert_operational_error(self.verify(archive, "30s"), diagnostic)
                self.assert_preflight(
                    self.compare(f"invalid {archive}", (self.dense, archive), max_gap="30s", promtool=stub), marker, diagnostic,
                )

        legacy, _ = invalid[-1]
        result, machine, _ = self.compare("manifestless normal", (legacy,))
        self.assert_exit(result, 0)
        self.assertNotIn("bundle_coverage", json.loads(machine.read_bytes()))

    def test_invalid_coverage_threshold_is_an_operational_error(self):
        stub, marker = self.promtool_stub()
        for limit in ("0ms", "soon", "-1ms"):
            with self.subTest(limit=limit):
                diagnostic = r"(?i)max.gap|duration|positive"
                self.assert_operational_error(self.verify(self.dense, limit), diagnostic)
                self.assert_preflight(
                    self.compare(f"invalid limit-{limit}", (self.dense,), max_gap=limit, promtool=stub), marker, diagnostic,
                )

    @unittest.skipUnless(shutil.which("git"), "Git is required to pin capture evidence")
    def test_git_batch_gate_reads_coverage_evidence_only_from_bundle_ref(self):
        repo = self.workspace / "pinned coverage checkout"
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

        git("init", "--quiet")
        (repo / "captures").mkdir()
        archives = (f"captures/{self.sparse}", f"captures/{self.dense}")
        for archive, source in zip(archives, (self.sparse, self.dense), strict=True):
            shutil.copyfile(self.workspace / source, repo / archive)
        git("add", "--", ".")
        git("commit", "--quiet", "-m", "Store original incident bundles")
        before = git("rev-parse", "HEAD")

        candidate = "candidate [proposed].yml"
        shutil.copyfile(SLOW, repo / candidate)
        (repo / archives[0]).write_bytes(b"no usable bundle in newer commit")
        (repo / archives[1]).unlink()
        git("add", "--", ".")
        git("commit", "--quiet", "-m", "Change rules and invalidate candidate copies of evidence")
        after = git("rev-parse", "HEAD")
        (repo / candidate).write_bytes(b"invalid working rule")
        dirty = git("status", "--porcelain=v1")

        report = self.assert_compare_coverage(
            self.compare("pinned batch", archives, max_gap="30s", rules=(
                "--repo", repo, "--bundle-ref", "HEAD^", "--after-ref", "HEAD", "--rule-file", candidate,
            )),
            1, 30_000, [(archives[0], False), (archives[1], True)], tests=6, failures=1,
        )
        self.assertEqual(report["commits"], {"before": before, "after": after})
        self.assertEqual(git("rev-parse", "HEAD"), after)
        self.assertEqual(git("status", "--porcelain=v1"), dirty)


if __name__ == "__main__":
    unittest.main()
