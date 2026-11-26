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
ALERT_NAME = "PaymentErrorsHigh"
ANNOTATION = "Payment service is returning HTTP 500 responses"


def webhook_alert(name=ALERT_NAME, *, status="firing", cluster="primary", summary=ANNOTATION):
    return {
        "status": status,
        "labels": {"alertname": name, "severity": "page", "cluster": cluster},
        "annotations": {"summary": summary},
        "startsAt": "2025-01-01T00:05:30Z",
        "endsAt": "0001-01-01T00:00:00Z",
        "generatorURL": "https://example.invalid/graph",
        "fingerprint": f"{name}-{status}-{cluster}",
    }


class AlertmanagerCaptureIntegrationTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        self.config_dir = self.workspace / "incident config"
        self.cwd = self.workspace / "outside"
        self.cwd.mkdir()
        self.config = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        self.config["expectations"][1] = {
            "at": "7m",
            "alertname": ALERT_NAME,
            "alertmanager_webhook": "captures/payment webhook.json",
            "drop_labels": ["cluster"],
        }
        self.webhook = {
            "version": "4",
            "groupKey": "{}",
            "truncatedAlerts": 0,
            "status": "firing",
            "receiver": "incident-fixtures",
            "groupLabels": {"alertname": ALERT_NAME},
            "commonLabels": {"alertname": ALERT_NAME, "severity": "page"},
            "commonAnnotations": {"summary": ANNOTATION},
            "externalURL": "https://example.invalid/alertmanager",
            "alerts": [
                webhook_alert(status="resolved", summary="Resolved alert to ignore"),
                webhook_alert("DifferentAlert", summary="Different firing alert to ignore"),
                webhook_alert(),
                webhook_alert(cluster="backup"),
            ],
        }

    def generate(self, name="payment.test.yml"):
        config_path = self.config_dir / "incident.json"
        webhook_path = self.config_dir / self.config["expectations"][1]["alertmanager_webhook"]
        webhook_path.parent.mkdir(parents=True, exist_ok=True)
        webhook_path.write_text(json.dumps(self.webhook), encoding="utf-8")
        config_path.write_text(json.dumps(self.config), encoding="utf-8")
        output = self.cwd / name
        result = subprocess.run(
            [
                sys.executable, CLI, config_path, "--matrix", DEMO / "incident.matrix.json",
                "--rule-file", DEMO / "after.rules.yml", "--output", output,
            ],
            cwd=self.cwd, capture_output=True, text=True, timeout=30,
        )
        return result, output

    def assert_rejected(self, result, output, diagnostic):
        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(result.stdout, "")
        self.assertRegex(result.stderr, diagnostic)
        self.assertFalse(output.exists())

    def test_config_relative_import_filters_and_deduplicates_projected_alerts(self):
        decoy = self.cwd / self.config["expectations"][1]["alertmanager_webhook"]
        decoy.parent.mkdir()
        decoy.write_text("not the selected webhook", encoding="utf-8")
        annotations = {"summary": ANNOTATION, "runbook_url": "https://example.invalid/payment-runbook"}
        for alert in self.webhook["alerts"][-2:]:
            alert["annotations"] = dict(annotations)
        self.webhook["alerts"].append({"status": "firing", "labels": {"service": "inventory"}})

        result, output = self.generate()

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        fixture = json.loads(output.read_text(encoding="utf-8"))
        group, = fixture["tests"]
        self.assertEqual(group["alert_rule_test"], [
            {"alertname": ALERT_NAME, "eval_time": "90s", "exp_alerts": []},
            {
                "alertname": ALERT_NAME,
                "eval_time": "420s",
                "exp_alerts": [{"exp_labels": {"severity": "page"}, "exp_annotations": annotations}],
            },
        ])

    @unittest.skipUnless(shutil.which(os.environ.get("PROMTOOL", "promtool")), "promtool is unavailable")
    def test_demo_fixture_with_no_truncation_field_passes_real_promtool(self):
        del self.webhook["truncatedAlerts"]
        generation, output = self.generate()
        self.assertEqual(generation.returncode, 0, f"{generation.stdout}\n{generation.stderr}")
        promtool = Path(shutil.which(os.environ.get("PROMTOOL", "promtool"))).resolve()

        result = subprocess.run(
            [promtool, "test", "rules", output],
            cwd=self.cwd, capture_output=True, text=True, timeout=30,
        )

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")

    def test_webhook_version_must_be_the_string_four(self):
        for index, version in enumerate(("3", 4, None)):
            with self.subTest(version=version):
                self.webhook["version"] = version
                result, output = self.generate(f"wrong-version-{index}.test.yml")

                self.assert_rejected(result, output, r"(?i)version")

    def test_truncated_webhook_cannot_produce_a_fixture(self):
        self.webhook["truncatedAlerts"] = 1

        result, output = self.generate()

        self.assert_rejected(result, output, r"(?i)truncat")

    def test_no_matching_firing_alert_is_an_error(self):
        self.webhook["alerts"] = self.webhook["alerts"][:2]

        result, output = self.generate()

        self.assert_rejected(result, output, r"(?i)no.*firing|firing.*match")

    def test_matching_projected_labels_with_conflicting_annotations_are_rejected(self):
        self.webhook["alerts"][-1]["annotations"]["summary"] = "Different recording for the same projected alert"

        result, output = self.generate()

        self.assert_rejected(result, output, r"(?i)conflict|same labels|different annotations")

    def test_webhook_and_manual_alerts_cannot_share_a_checkpoint(self):
        self.config["expectations"][1]["alerts"] = []

        result, output = self.generate()

        self.assert_rejected(result, output, r"(?i)alerts.*webhook|webhook.*alerts|exactly one")


if __name__ == "__main__":
    unittest.main()
