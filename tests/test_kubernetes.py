import importlib.util
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
RULE_API = "monitoring.coreos.com/v1"
HAS_YAML = importlib.util.find_spec("yaml") is not None


def prometheus_rule(name, *, version=None, groups=None):
    if version is not None:
        import yaml

        native_rule = DEMO / f"{version}.rules.yml"
        groups = yaml.safe_load(native_rule.read_text(encoding="utf-8"))["groups"]
    return {
        "apiVersion": RULE_API,
        "kind": "PrometheusRule",
        "metadata": {"name": name, "namespace": "monitoring"},
        "spec": {"groups": groups},
    }


class KubernetesTestCase(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)

    def cli(self, *arguments, without_site_packages=False):
        interpreter = [sys.executable, "-S"] if without_site_packages else [sys.executable]
        return subprocess.run(
            [*interpreter, CLI, *arguments], cwd=self.workspace, capture_output=True, text=True, timeout=30,
        )

    def write_manifest(self, filename, *documents):
        import yaml

        path = self.workspace / filename
        path.write_text(yaml.safe_dump_all(documents, explicit_start=True), encoding="utf-8")
        return path

    def capture_fixture(self, *, without_site_packages=False):
        fixture = self.workspace / "payment.test.yml"
        result = self.cli(
            DEMO / "demo.json", "--matrix", DEMO / "incident.matrix.json", "--output", fixture,
            without_site_packages=without_site_packages,
        )
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        return fixture


class KubernetesCommandTests(KubernetesTestCase):
    def test_yaml_dependency_is_only_required_for_kubernetes(self):
        self.assertTrue(self.capture_fixture(without_site_packages=True).is_file())
        manifest = self.workspace / "rule.yml"
        manifest.write_text(
            f"apiVersion: {RULE_API}\nkind: PrometheusRule\nspec:\n"
            "  groups: [{name: check, rules: [{alert: Check, expr: vector(1)}]}]\n",
            encoding="utf-8",
        )
        output = self.workspace / "exported"
        result = self.cli("export-rules", manifest, "--output-dir", output, without_site_packages=True)

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertIn("PyYAML", result.stderr)
        self.assertFalse(output.exists())

    @unittest.skipUnless(HAS_YAML, "PyYAML unavailable")
    def test_exports_lists_and_keeps_same_named_groups_in_separate_files(self):
        import yaml

        before = prometheus_rule("payment-before", version="before")
        after = prometheus_rule("payment-after", version="after")
        typed_item = {key: after[key] for key in ("metadata", "spec")}
        generic_list = self.write_manifest(
            "generic.yml", {"apiVersion": "v1", "kind": "List", "items": [
                {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "unrelated"}}, before,
            ]},
        )
        typed_list = self.write_manifest(
            "typed.yml", {"apiVersion": RULE_API, "kind": "PrometheusRuleList", "items": [typed_item]},
        )
        output = self.workspace / "exported"

        result = self.cli("export-rules", generic_list, typed_list, "--output-dir", output)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(sorted(item.name for item in output.iterdir()), ["rules-1.yml", "rules-2.yml"])
        for rule, filename in ((before, "rules-1.yml"), (after, "rules-2.yml")):
            exported = yaml.safe_load((output / filename).read_text(encoding="utf-8"))
            self.assertEqual(exported, {"groups": rule["spec"]["groups"]})

    @unittest.skipUnless(HAS_YAML, "PyYAML unavailable")
    def test_invalid_or_empty_manifest_leaves_no_output_directory(self):
        valid = prometheus_rule("payment", version="before")
        output = self.workspace / "exported"
        invalid_cases = (
            (valid, prometheus_rule("invalid", groups="not a list")),
            (valid, prometheus_rule("missing-group-name", groups=[{"rules": []}])),
            (valid, prometheus_rule("invalid-rules", groups=[{"name": "invalid", "rules": ["wrong"]}])),
            (valid, {**valid, "apiVersion": "monitoring.coreos.com/v1beta1"}),
            ({**valid, "spec": {}},),
            ({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "unrelated"}},),
        )

        for documents in invalid_cases:
            with self.subTest(documents=documents):
                manifest = self.write_manifest("invalid.yml", *documents)
                result = self.cli("export-rules", manifest, "--output-dir", output)

                self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
                self.assertRegex(result.stderr, r"(?i)PrometheusRule|groups|manifest")
                self.assertFalse(output.exists())

    @unittest.skipUnless(HAS_YAML, "PyYAML unavailable")
    def test_duplicate_yaml_keys_are_rejected(self):
        manifest = self.workspace / "duplicate.yml"
        manifest.write_text(
            f"apiVersion: {RULE_API}\nkind: PrometheusRule\nspec:\n"
            "  groups: []\n  groups: [{name: duplicate, rules: []}]\n",
            encoding="utf-8",
        )
        output = self.workspace / "exported"

        result = self.cli("export-rules", manifest, "--output-dir", output)

        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertIn("duplicate mapping key 'groups'", result.stderr)
        self.assertIn("duplicate.yml", result.stderr)
        self.assertFalse(output.exists())

    @unittest.skipUnless(HAS_YAML, "PyYAML unavailable")
    def test_yaml_merge_overrides_are_preserved_in_prometheus_groups(self):
        import yaml

        manifest = self.workspace / "anchors.yml"
        manifest.write_text(
            f"apiVersion: {RULE_API}\nkind: PrometheusRule\nspec:\n  groups:\n"
            "    - &group\n      name: first\n      partial_response_strategy: abort\n"
            "      rules: [{alert: Check, expr: vector(1)}]\n"
            "    - <<: *group\n      name: second\n",
            encoding="utf-8",
        )
        output = self.workspace / "exported"

        result = self.cli("export-rules", manifest, "--output-dir", output)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        groups = yaml.safe_load((output / "rules-1.yml").read_text(encoding="utf-8"))["groups"]
        self.assertEqual(groups, [
            {"name": name, "rules": [{"alert": "Check", "expr": "vector(1)"}]}
            for name in ("first", "second")
        ])


@unittest.skipUnless(HAS_YAML, "PyYAML unavailable")
class KubernetesCompareTests(KubernetesTestCase):
    def setUp(self):
        super().setUp()
        promtool = shutil.which(os.environ.get("PROMTOOL", "promtool"))
        if promtool is None:
            self.skipTest("promtool unavailable; set PROMTOOL to its path")
        self.promtool = Path(promtool).resolve()
        self.fixture = self.capture_fixture()
        self.fixture_content = self.fixture.read_bytes()
        self.fixture_stat = self.fixture.stat()

    def compare(self, *arguments):
        result = self.cli(
            "compare", self.fixture, "--rule-format", "kubernetes", "--promtool", self.promtool, *arguments,
        )
        self.assertEqual(self.fixture.read_bytes(), self.fixture_content)
        self.assertEqual(self.fixture.stat().st_ino, self.fixture_stat.st_ino)
        self.assertEqual(self.fixture.stat().st_mtime_ns, self.fixture_stat.st_mtime_ns)
        return result

    def assert_comparison(self, result, code, before, after):
        self.assertEqual(result.returncode, code, f"{result.stdout}\n{result.stderr}")
        self.assertIn("PaymentErrorsHigh", result.stdout)
        self.assertRegex(result.stdout, rf"(?im)^[^\n]*\bbefore\b[^\n]*\b{before}\b[^\n]*$")
        self.assertRegex(result.stdout, rf"(?im)^[^\n]*\bafter\b[^\n]*\b{after}\b[^\n]*$")

    def test_compares_rendered_multidocument_manifests_against_native_fixture(self):
        config = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "unrelated"}}
        before = self.write_manifest("before.yml", None, config, prometheus_rule("payment", version="before"))
        after = self.write_manifest("after.yml", prometheus_rule("payment", version="after"), config)

        result = self.compare("--before", before, "--after", after)

        self.assert_comparison(result, 0, "Failed", "Passed")

    @unittest.skipUnless(shutil.which("git"), "git unavailable")
    def test_git_ref_comparison_detects_a_regression_with_dirty_checkout(self):
        import yaml

        repo = self.workspace / "repo"
        repo.mkdir()

        def git(*arguments):
            return subprocess.run(
                ["git", "-C", repo, *arguments], check=True, capture_output=True, text=True, timeout=30,
            ).stdout

        git("init", "--quiet")
        git("config", "--local", "user.name", "Integration Test")
        git("config", "--local", "user.email", "test@example.invalid")
        git("config", "--local", "commit.gpgsign", "false")
        git("config", "--local", "core.hooksPath", os.devnull)
        rule_path = "manifests/payment alerts.yml"
        rule = repo / rule_path
        rule.parent.mkdir()
        for version in ("after", "before"):
            document = prometheus_rule("payment", version=version)
            rule.write_text(yaml.safe_dump(document), encoding="utf-8")
            git("add", "--", rule_path)
            git("commit", "--quiet", "-m", f"Add {version} payment rule")
        rule.write_text("broken: [working tree\n", encoding="utf-8")
        checkout = git("status", "--porcelain=v1")

        result = self.compare(
            "--repo", repo, "--before-ref", "HEAD^", "--after-ref", "HEAD", "--rule-file", rule_path,
        )

        self.assert_comparison(result, 1, "Passed", "Failed")
        self.assertEqual(rule.read_text(encoding="utf-8"), "broken: [working tree\n")
        self.assertEqual(git("status", "--porcelain=v1"), checkout)


if __name__ == "__main__":
    unittest.main()
