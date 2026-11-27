from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from threading import Thread
import unittest
from urllib.parse import parse_qs, urlsplit

try:
    import ssl
except ImportError:
    ssl = None


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
TOKEN = "prometheus-tls-test-token"
CAPTURE_COMMANDS = (
    ("generate", "fixture.test.yml", 1),
    ("bundle", "incident.zip", 1),
    ("snapshot", "snapshot.json", 1),
    ("inspect", None, 2),
)


@unittest.skipIf(ssl is None, "Python SSL support is required for HTTPS tests")
class PrometheusTLSIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            raise unittest.SkipTest("openssl is required for ephemeral TLS certificates")
        certificates = tempfile.TemporaryDirectory()
        cls.addClassCleanup(certificates.cleanup)
        cls.certificates = Path(certificates.name)
        config = cls.certificates / "openssl.cnf"
        config.write_text(
            "[req]\n"
            "distinguished_name = subject\n"
            "[subject]\n"
            "[root_ca]\n"
            "basicConstraints = critical, CA:TRUE\n"
            "keyUsage = critical, keyCertSign, cRLSign\n"
            "subjectKeyIdentifier = hash\n"
            "[server]\n"
            "basicConstraints = critical, CA:FALSE\n"
            "keyUsage = critical, digitalSignature, keyEncipherment\n"
            "extendedKeyUsage = serverAuth\n"
            "subjectAltName = IP:127.0.0.1\n"
            "[wrong_host]\n"
            "basicConstraints = critical, CA:FALSE\n"
            "keyUsage = critical, digitalSignature, keyEncipherment\n"
            "extendedKeyUsage = serverAuth\n"
            "subjectAltName = IP:127.0.0.2\n",
            encoding="ascii",
        )
        for name in ("capture-ca", "other-ca"):
            cls.run_openssl(
                "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
                "-subj", f"/CN={name}", "-config", config, "-extensions", "root_ca",
                "-keyout", f"{name}.key", "-out", f"{name}.pem",
            )
        cls.ca = cls.certificates / "capture-ca.pem"
        cls.unsuitable_ca = cls.certificates / "other-ca.pem"
        cls.leaf_key = cls.certificates / "leaf.key"
        cls.run_openssl(
            "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=ephemeral-prometheus",
            "-config", config, "-keyout", cls.leaf_key, "-out", "leaf.csr",
        )
        for section, serial in (("server", "1"), ("wrong_host", "2")):
            cls.run_openssl(
                "x509", "-req", "-in", "leaf.csr", "-CA", cls.ca, "-CAkey", "capture-ca.key",
                "-set_serial", serial, "-days", "2", "-sha256",
                "-extfile", config, "-extensions", section, "-out", f"{section}.pem",
            )
        cls.leaf = cls.certificates / "server.pem"
        cls.wrong_host = cls.certificates / "wrong_host.pem"

    @classmethod
    def run_openssl(cls, *options):
        result = subprocess.run(
            [cls.openssl, *options], cwd=cls.certificates, capture_output=True, text=True, timeout=20,
        )
        if result.returncode:
            raise AssertionError(f"Could not create test certificates:\n{result.stdout}{result.stderr}")

    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        self.matrix = json.loads((DEMO / "incident.matrix.json").read_text(encoding="utf-8"))
        self.token = self.workspace / "bearer.secret"
        self.token.write_text(f"{TOKEN}\n", encoding="ascii")
        self.plan_rules = self.workspace / "planner.rules.yml"
        self.plan_rules.write_text(
            "groups:\n- name: planner\n  rules:\n  - alert: CheckAvailability\n    expr: up\n",
            encoding="utf-8",
        )

    @contextmanager
    def server(self, *, certificate=None, response=None, redirect=None, require_alpn=False):
        requests, connections = [], []
        payload = self.matrix if response is None else response
        context = None
        if certificate is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, self.leaf_key)
            if require_alpn:
                context.set_alpn_protocols(["http/1.1"])

        class Server(HTTPServer):
            def get_request(self):
                client, address = super().get_request()
                connections.append(address)
                if context is not None:
                    try:
                        client = context.wrap_socket(client, server_side=True)
                    except OSError:
                        client.close()
                        raise
                return client, address

        class Handler(BaseHTTPRequestHandler):
            def handle_api(self):
                if require_alpn and self.connection.selected_alpn_protocol() != "http/1.1":
                    self.send_error(426, "Expected TLS ALPN http/1.1")
                    return
                url = urlsplit(self.path)
                form = url.query
                if self.command == "POST":
                    form = self.rfile.read(int(self.headers["Content-Length"])).decode("ascii")
                requests.append((self.command, url.path, parse_qs(form), self.headers.get("Authorization")))
                if redirect is not None:
                    self.send_response(302)
                    self.send_header("Location", redirect)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = handle_api
            do_POST = handle_api

            def log_message(self, *_arguments):
                pass

        with Server(("127.0.0.1", 0), Handler) as server:
            worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            worker.start()
            try:
                host, port = server.server_address
                scheme = "https" if context is not None else "http"
                yield f"{scheme}://{host}:{port}", requests, connections
            finally:
                server.shutdown()
                worker.join(timeout=5)

    def invoke(self, mode, filename=None, *, url=None, ca=None, bearer=False, default_ca=None):
        command = [sys.executable, CLI]
        if mode == "plan-capture":
            command.extend((mode, self.plan_rules, "--alertname", "CheckAvailability"))
        else:
            if mode != "generate":
                command.append(mode)
            command.append(DEMO / "demo.json")
        if url is None:
            command.extend(("--matrix", DEMO / "incident.matrix.json"))
        else:
            command.extend(("--prometheus-url", url))
        if ca is not None:
            command.extend(("--ca-file", ca))
        if bearer:
            command.extend(("--bearer-token-file", self.token))
        if mode == "inspect":
            command.extend(("--format", "json"))
        output = self.workspace / filename if filename is not None else None
        if output is not None:
            command.extend(("--output", output))
        environment = {**os.environ, "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}
        for variable in ("PROMETHEUS_BEARER_TOKEN", "SSL_CERT_FILE", "SSL_CERT_DIR"):
            environment.pop(variable, None)
        if default_ca is not None:
            environment["SSL_CERT_FILE"] = str(default_ca)
        result = subprocess.run(command, cwd=self.workspace, env=environment, capture_output=True, text=True, timeout=30)
        return result, output

    def assert_failed(self, outcome, exit_code, diagnostic):
        result, output = outcome
        self.assertEqual(result.returncode, exit_code, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(result.stdout, "")
        self.assertRegex(result.stderr, diagnostic)
        self.assertNotIn(TOKEN, result.stderr)
        if output is not None:
            self.assertFalse(output.exists())

    def test_https_capture_commands_trust_the_custom_ca_and_send_bearer(self):
        with self.server(certificate=self.leaf, require_alpn=ssl.HAS_ALPN) as (url, requests, _):
            for mode, filename, _ in CAPTURE_COMMANDS:
                with self.subTest(mode=mode):
                    result, output = self.invoke(mode, filename, url=f"{url}/prom", ca=self.ca, bearer=True)

                    self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
                    self.assertNotIn(TOKEN, result.stdout + result.stderr)
                    if mode == "inspect":
                        self.assertEqual(json.loads(result.stdout)["sample_count"], 21)
                    elif mode == "snapshot":
                        self.assertEqual(json.loads(output.read_bytes()), self.matrix)
                    else:
                        self.assertTrue(output.is_file())

        self.assertEqual(requests, [
            ("GET", "/prom/api/v1/query", {
                "query": ['payment_http_requests_total{code="500"}[600001ms]'], "time": ["2025-01-01T00:10:00+00:00"],
            }, f"Bearer {TOKEN}")
        ] * len(CAPTURE_COMMANDS))

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML unavailable")
    def test_planner_can_post_through_custom_ca(self):
        ast = {"status": "success", "data": {
            "type": "vectorSelector", "name": "up",
            "matchers": [{"name": "__name__", "type": "=", "value": "up"}],
            "offset": 0, "timestamp": None, "startOrEnd": None,
        }}
        with self.server(certificate=self.leaf, response=ast) as (url, requests, _):
            result, _ = self.invoke("plan-capture", url=url, ca=self.ca, bearer=True)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(json.loads(result.stdout)["selectors"], ["up"])
        self.assertEqual(requests, [("POST", "/api/v1/parse_query", {"query": ["up"]}, f"Bearer {TOKEN}")])

    def test_peer_certificate_and_ip_address_are_still_verified(self):
        cases = (
            ("untrusted", self.leaf, None, r"(?i)certificate verify failed|unknown issuer|self.signed"),
            ("wrong ip", self.wrong_host, self.ca, r"(?i)ip address mismatch|not valid for|host ?name mismatch"),
        )
        for name, certificate, ca, diagnostic in cases:
            with self.subTest(case=name):
                with self.server(certificate=certificate) as (url, requests, connections):
                    outcome = self.invoke("snapshot", f"{name}.json", url=url, ca=ca, bearer=True)

                self.assert_failed(outcome, 1, diagnostic)
                self.assertEqual(len(connections), 1)
                self.assertEqual(requests, [])

    def test_explicit_ca_augments_the_default_trust_store(self):
        with self.server(certificate=self.leaf) as (url, requests, _):
            result, output = self.invoke(
                "snapshot", "default and custom.json", url=url, ca=self.unsuitable_ca, default_ca=self.ca,
            )

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertTrue(output.is_file())
        self.assertEqual(len(requests), 1)

    def test_bad_ca_files_fail_before_connecting_and_offline_use_is_rejected(self):
        missing = self.workspace / "missing root.pem"
        malformed = self.workspace / "malformed root.pem"
        malformed.write_text("not a PEM certificate\n", encoding="ascii")
        with self.server(certificate=self.leaf) as (url, requests, connections):
            for ca in (missing, malformed):
                with self.subTest(ca=ca.name):
                    self.assert_failed(
                        self.invoke("snapshot", "bad root.json", url=url, ca=ca), 1,
                        r"(?i)ca.file|certificate|pem|no such file",
                    )
        self.assertEqual(connections, [])
        self.assertEqual(requests, [])

        for mode, filename, _ in CAPTURE_COMMANDS:
            with self.subTest(mode=mode):
                self.assert_failed(self.invoke(mode, filename, ca=missing), 2, r"(?i)ca.file.*(?:prometheus-url|https)")

    def test_plain_http_with_custom_ca_fails_before_connecting(self):
        with self.server() as (url, requests, connections):
            for mode, filename, exit_code in (*CAPTURE_COMMANDS, ("plan-capture", None, 2)):
                with self.subTest(mode=mode):
                    outcome = self.invoke(mode, filename, url=url, ca=self.ca)
                    self.assert_failed(outcome, exit_code, r"(?i)https")
        self.assertEqual(connections, [])
        self.assertEqual(requests, [])

    def test_https_redirect_keeps_ca_validation_without_forwarding_bearer(self):
        with self.server(certificate=self.leaf) as (destination, redirected, _):
            with self.server(certificate=self.leaf, redirect=f"{destination}/destination") as (url, source, _):
                result, output = self.invoke("snapshot", "https redirect.json", url=url, ca=self.ca, bearer=True)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertTrue(output.is_file())
        self.assertEqual([request[3] for request in source], [f"Bearer {TOKEN}"])
        self.assertEqual(redirected, [("GET", "/destination", {}, None)])

    def test_http_downgrade_is_blocked_with_custom_ca_and_default_transport_is_unchanged(self):
        with self.server() as (destination, redirected, connections):
            with self.server(certificate=self.leaf, redirect=f"{destination}/destination") as (url, source, _):
                secure = self.invoke("snapshot", "downgrade blocked.json", url=url, ca=self.ca, bearer=True)
                self.assert_failed(secure, 1, r"(?i)redirect|https")
                self.assertEqual(connections, [])
                self.assertEqual(redirected, [])

                result, output = self.invoke("snapshot", "default redirect.json", url=url, default_ca=self.ca, bearer=True)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertTrue(output.is_file())
        self.assertEqual([request[3] for request in source], [f"Bearer {TOKEN}", f"Bearer {TOKEN}"])
        self.assertEqual(redirected, [("GET", "/destination", {}, None)])


if __name__ == "__main__":
    unittest.main()
