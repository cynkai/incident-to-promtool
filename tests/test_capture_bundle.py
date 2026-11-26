from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
ANNOTATION = "Payment service is returning HTTP 500 responses"
BASE_MEMBERS = ["incident.json", "incident.matrix.json", "incident.test.yml", "capture.json", "coverage.json", "manifest.json"]


class CaptureBundleIntegrationTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        self.origin = self.workspace / "original capture"
        self.origin.mkdir()
        self.config_path = self.origin / "source incident.json"
        self.matrix_path = self.origin / "source matrix.json"
        self.config = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        self.matrix = json.loads((DEMO / "incident.matrix.json").read_text(encoding="utf-8"))
        self.rule = self.origin / "native rules" / "payment alerts.yml"
        self.rule.parent.mkdir()
        self.rule.write_bytes((DEMO / "after.rules.yml").read_bytes())
        self.config["rule_files"] = [self.rule.relative_to(self.origin).as_posix()]

    def run_cli(self, *arguments, cwd=None):
        return subprocess.run(
            [sys.executable, CLI, *arguments], cwd=cwd or self.workspace,
            capture_output=True, text=True, timeout=30,
        )

    def bundle(self, filename, *options, matrices=None):
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        self.matrix_path.write_text(json.dumps(self.matrix), encoding="utf-8")
        archive = self.workspace / filename
        command = ["bundle", self.config_path, "--output", archive, *options]
        for path in (self.matrix_path,) if matrices is None else matrices:
            command.extend(("--matrix", path))
        return self.run_cli(*command), archive

    def extract(self, result, archive, destination):
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        extracted = self.workspace / destination
        with ZipFile(archive) as bundle:
            bundle.extractall(extracted)
        return extracted

    def assert_offline_replay_matches(self, extracted, options=()):
        result = self.run_cli(
            "incident.json", "--matrix", "incident.matrix.json", "--output", "regenerated.test.yml", *options,
            cwd=extracted,
        )
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertEqual((extracted / "regenerated.test.yml").read_bytes(), (extracted / "incident.test.yml").read_bytes())

    def test_relocated_bundle_replays_without_original_sources(self):
        webhook = self.origin / "captured notifications" / "source webhook.json"
        webhook.parent.mkdir()
        webhook.write_text(json.dumps({
            "version": "4",
            "externalURL": "https://original-webhook-source.example.invalid",
            "alerts": [{
                "status": "firing",
                "labels": {"alertname": "PaymentErrorsHigh", "severity": "page", "cluster": "external"},
                "annotations": {"summary": ANNOTATION},
            }],
        }), encoding="utf-8")
        self.config["selectors"] = ['payment_http_requests_total{metadata="original-selector-sentinel"}']
        self.config["prometheus_url"] = "https://fixture-user:original-password@example.invalid"
        self.config["expectations"][1] = {
            "at": "7m", "alertname": "PaymentErrorsHigh",
            "alertmanager_webhook": webhook.relative_to(self.origin).as_posix(), "drop_labels": ["cluster"],
        }
        rule_contents = self.rule.read_bytes()

        result, archive = self.bundle("original capture/fresh archive.zip")
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        moved = self.workspace / "moved archive.zip"
        archive.rename(moved)
        shutil.rmtree(self.origin)
        extracted = self.extract(result, moved, "detached bundle")

        with ZipFile(moved) as bundle:
            members = [entry.filename for entry in bundle.infolist() if not entry.is_dir()]
            self.assertCountEqual(members, [*BASE_MEMBERS, "rules/rules-1.yml"])
            for name in members:
                content = bundle.read(name)
                self.assertNotIn(b"original-webhook-source", content)
                self.assertNotIn(b"original-selector-sentinel", content)
                self.assertNotIn(b"original-password", content)
        portable = json.loads((extracted / "incident.json").read_text(encoding="utf-8"))
        self.assertEqual(portable["rule_files"], ["rules/rules-1.yml"])
        self.assertNotIn("selectors", portable)
        self.assertNotIn("prometheus_url", portable)
        first, second = portable["expectations"]
        for expectation in (first, second):
            self.assertEqual(set(expectation), {"at", "alertname", "alerts"})
        self.assertEqual(first["alerts"], [])
        self.assertEqual(second["alerts"], [{"labels": {"severity": "page"}, "annotations": {"summary": ANNOTATION}}])
        self.assertEqual((extracted / "rules/rules-1.yml").read_bytes(), rule_contents)

        capture = json.loads((extracted / "capture.json").read_text(encoding="utf-8"))
        fixture = extracted / "incident.test.yml"
        self.assertEqual(capture["schema_version"], 1)
        self.assertEqual(capture["bundle_manifest_version"], 1)
        self.assertEqual(capture["fixture_path"], "incident.test.yml")
        self.assertEqual(capture["fixture_sha256"], hashlib.sha256(fixture.read_bytes()).hexdigest())
        self.assertEqual(capture["generation_options"], [])
        self.assertEqual(json.loads(fixture.read_text(encoding="utf-8"))["rule_files"], portable["rule_files"])
        coverage = json.loads((extracted / "coverage.json").read_text(encoding="utf-8"))
        self.assertEqual(coverage["schema_version"], 1)
        self.assertIsNone(coverage["gate"])
        self.assertEqual((coverage["series_count"], coverage["sample_count"]), (1, 21))
        self.assert_offline_replay_matches(extracted, capture["generation_options"])

        promtool = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        if promtool:
            replay = subprocess.run(
                [Path(promtool).resolve(), "test", "rules", "incident.test.yml"],
                cwd=extracted, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(replay.returncode, 0, f"{replay.stdout}\n{replay.stderr}")

    def test_rule_overrides_deduplicate_resolved_paths_without_basename_collision(self):
        self.config["rule_files"] = ["unused/missing.rule.yml"]
        extra = self.origin / "other rules" / self.rule.name
        extra.parent.mkdir()
        extra.write_text("groups:\n- name: auxiliary\n  rules:\n  - record: auxiliary_total\n    expr: vector(1)\n", encoding="utf-8")
        alias = self.origin / "same resolved payment rule.yml"
        alias.symlink_to(self.rule)

        result, archive = self.bundle("overrides.zip", "--rule-file", extra, "--rule-file", self.rule, "--rule-file", alias)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        with ZipFile(archive) as bundle:
            members = [entry.filename for entry in bundle.infolist() if not entry.is_dir()]
            self.assertCountEqual(members, [*BASE_MEMBERS, "rules/rules-1.yml", "rules/rules-2.yml"])
            self.assertEqual(bundle.read("rules/rules-1.yml"), extra.read_bytes())
            self.assertEqual(bundle.read("rules/rules-2.yml"), self.rule.read_bytes())
            config = json.loads(bundle.read("incident.json"))
            fixture = json.loads(bundle.read("incident.test.yml"))
            self.assertEqual(config["rule_files"], ["rules/rules-1.yml", "rules/rules-2.yml"])
            self.assertEqual(fixture["rule_files"], config["rule_files"])

    def test_round_up_keeps_off_grid_capture_and_records_replay_option(self):
        samples = self.matrix["data"]["result"][0]["values"]
        samples[1][0] = samples[0][0] + 29.999

        result, archive = self.bundle("rounded.zip", "--round-up")

        extracted = self.extract(result, archive, "rounded bundle")
        capture = json.loads((extracted / "capture.json").read_text(encoding="utf-8"))
        self.assertEqual(capture["generation_options"], ["--round-up"])
        self.assertEqual(capture["sampling_mode"], "fixed_round_up")
        self.assertEqual(capture["max_shift_ms"], 1)
        self.assertEqual(capture["shifted_sample_count"], 1)
        raw = json.loads((extracted / "incident.matrix.json").read_text(encoding="utf-8"), parse_float=Decimal)
        self.assertEqual(raw["data"]["result"][0]["values"][1], [Decimal("1735689629.999"), "0"])
        coverage = json.loads((extracted / "coverage.json").read_text(encoding="utf-8"))
        self.assertEqual(coverage["series"][0]["max_sample_gap"]["duration_ms"], 30_001)
        self.assert_offline_replay_matches(extracted, capture["generation_options"])

    def test_max_shift_option_preserves_the_supplied_duration(self):
        samples = self.matrix["data"]["result"][0]["values"]
        start = samples[0][0]
        samples[:] = [[start, "0"], [start + 0.001, "1"], [start + 2_000, "2"]]
        self.config["sample_interval"] = "auto"
        self.config["end"] = "2025-01-01T00:33:20Z"

        result, archive = self.bundle("bounded.zip", "--max-shift", "002ms")

        extracted = self.extract(result, archive, "bounded bundle")
        capture = json.loads((extracted / "capture.json").read_text(encoding="utf-8"))
        self.assertEqual(capture["generation_options"], ["--max-shift", "002ms"])
        self.assertEqual(capture["sampling_mode"], "auto_bounded")
        self.assertEqual(capture["sample_interval_ms"], 2)
        self.assertEqual(capture["max_shift_limit_ms"], 2)
        self.assert_offline_replay_matches(extracted, capture["generation_options"])

    def test_errors_never_replace_or_leave_a_partial_archive(self):
        first, archive = self.bundle("protected.zip")
        self.assertEqual(first.returncode, 0, f"{first.stdout}\n{first.stderr}")
        original = archive.read_bytes()
        inode = archive.stat().st_ino

        repeated, _ = self.bundle(archive.name)

        self.assertEqual(repeated.returncode, 1, f"{repeated.stdout}\n{repeated.stderr}")
        self.assertRegex(repeated.stderr, r"(?i)exist|overwrite")
        self.assertEqual(archive.read_bytes(), original)
        self.assertEqual(archive.stat().st_ino, inode)

        conflict = self.origin / "conflicting capture.json"
        series = self.matrix["data"]["result"][0]
        conflict.write_text(json.dumps({
            "status": "success", "data": {"resultType": "matrix", "result": [
                {"metric": series["metric"], "values": [[series["values"][0][0], "999"]]},
            ]},
        }), encoding="utf-8")
        invalid, partial = self.bundle("partial.zip", matrices=(self.matrix_path, conflict))

        self.assertEqual(invalid.returncode, 1, f"{invalid.stdout}\n{invalid.stderr}")
        self.assertRegex(invalid.stderr, r"(?i)conflict")
        self.assertFalse(partial.exists())

        missing, missing_archive = self.bundle("missing-source.zip", matrices=())

        self.assertEqual(missing.returncode, 2, f"{missing.stdout}\n{missing.stderr}")
        self.assertFalse(missing_archive.exists())


if __name__ == "__main__":
    unittest.main()
