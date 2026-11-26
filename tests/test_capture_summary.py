from copy import deepcopy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"


class CaptureSummaryIntegrationTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        self.config = json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))
        self.matrix = json.loads((DEMO / "incident.matrix.json").read_text(encoding="utf-8"))
        self.series = self.matrix["data"]["result"]
        self.start = self.series[0]["values"][0][0]

    def generate(self, name, *options, summary=True, additional_matrices=()):
        config = self.workspace / "incident.json"
        config.write_text(json.dumps(self.config), encoding="utf-8")
        command = [sys.executable, CLI, config, "--rule-file", DEMO / "after.rules.yml", "--output", name, *options]
        for number, matrix in enumerate((self.matrix, *additional_matrices), start=1):
            capture = self.workspace / f"matrix-{number}.json"
            capture.write_text(json.dumps(matrix), encoding="utf-8")
            command.extend(("--matrix", capture))
        if summary:
            command.extend(("--summary-format", "json"))
        result = subprocess.run(command, cwd=self.workspace, capture_output=True, text=True, timeout=30)
        return result, self.workspace / name

    def assert_summary(self, result, fixture, **fields):
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        summary = json.loads(result.stdout)
        self.assertIs(type(summary["schema_version"]), int)
        self.assertEqual(summary["schema_version"], 1)
        self.assertEqual(summary["fixture_path"], fixture.relative_to(self.workspace).as_posix())
        self.assertEqual(summary["fixture_sha256"], hashlib.sha256(fixture.read_bytes()).hexdigest())
        self.assertEqual({key: summary[key] for key in fields}, fields)
        return summary

    def assert_utc(self, timestamp, expected):
        self.assertTrue(timestamp.endswith(("Z", "+00:00")), timestamp)
        self.assertEqual(datetime.fromisoformat(timestamp.replace("Z", "+00:00")), datetime.fromisoformat(expected))

    def test_exact_modes_count_unique_in_window_samples_and_hash_fixture(self):
        self.config["start"] = "2025-01-01T09:00:00+09:00"
        self.config["end"] = "2025-01-01T09:10:00+09:00"
        overlap = deepcopy(self.matrix)
        overlap["data"]["result"][0]["values"] = [
            [self.start - 1, "0"], [self.start, "0.0"], [self.start + 600, "960.0"], [self.start + 601, "960"],
        ]

        configurations = (
            ("auto", "auto_exact", None, ()),
            ("30s", "fixed_exact", None, ()),
            ("auto", "auto_exact", 2, ("--max-shift", "2ms")),
        )
        for interval, mode, shift_limit, options in configurations:
            with self.subTest(mode=mode, shift_limit=shift_limit):
                self.config["sample_interval"] = interval
                result, fixture = self.generate(f"{mode}-{shift_limit}.test.yml", *options, additional_matrices=(overlap,))
                summary = self.assert_summary(
                    result, fixture, sampling_mode=mode, evaluation_interval_ms=30_000, sample_interval_ms=30_000,
                    max_shift_ms=0, max_shift_limit_ms=shift_limit, series_count=1, sample_count=21,
                    shifted_sample_count=0, checkpoint_count=2, expanded_slots=21,
                )
                self.assert_utc(summary["start"], "2025-01-01T00:00:00+00:00")
                self.assert_utc(summary["end"], "2025-01-01T00:10:00+00:00")

    def test_bounded_mode_reports_actual_shift_count_limit_and_aggregate_slots(self):
        self.config["end"] = "2025-01-01T00:33:20Z"
        self.config["sample_interval"] = "auto"
        self.series[0]["values"] = [[self.start, "0"], [self.start + 0.001, "1"], [self.start + 2_000, "2"]]
        self.series.append({
            "metric": {"__name__": "payment_http_requests_total", "code": "200"},
            "values": [[self.start, "0"], [self.start + 0.005, "1"], [self.start + 1, "2"]],
        })

        result, fixture = self.generate("bounded.test.yml", "--max-shift", "2ms")

        self.assert_summary(
            result, fixture, sampling_mode="auto_bounded", evaluation_interval_ms=30_000, sample_interval_ms=2,
            max_shift_ms=1, max_shift_limit_ms=2, series_count=2, sample_count=6,
            shifted_sample_count=2, checkpoint_count=2, expanded_slots=1_000_502,
        )

    def test_fixed_rounding_reports_full_numeric_grid_limit(self):
        self.series[0]["values"] = [[self.start, "0"], [self.start + 31, "62"], [self.start + 600, "1200"]]

        result, fixture = self.generate("rounded.test.yml", "--round-up")

        self.assert_summary(
            result, fixture, sampling_mode="fixed_round_up", evaluation_interval_ms=30_000,
            sample_interval_ms=30_000, max_shift_ms=29_000, max_shift_limit_ms=29_999,
            series_count=1, sample_count=3, shifted_sample_count=1, checkpoint_count=2, expanded_slots=21,
        )

    def test_default_stdout_remains_human_readable(self):
        result, fixture = self.generate("default.test.yml", summary=False)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertTrue(fixture.is_file())
        self.assertEqual(result.stdout, "Wrote default.test.yml (1 series, 2 checkpoints).\n")

    def test_conflicting_sample_produces_no_fixture_or_summary(self):
        self.series[0]["values"].append([self.start, "999"])

        result, fixture = self.generate("conflict.test.yml")

        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(result.stdout, "")
        self.assertIn("conflicting values", result.stderr)
        self.assertFalse(fixture.exists())

    def test_existing_output_produces_no_summary_and_is_preserved(self):
        fixture = self.workspace / "existing.test.yml"
        original = b"keep this fixture\n"
        fixture.write_bytes(original)

        result, _ = self.generate(fixture.name)

        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(result.stdout, "")
        self.assertIn("output file already exists", result.stderr)
        self.assertEqual(fixture.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
