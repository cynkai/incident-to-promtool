from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from threading import Thread
import unittest
from urllib.parse import parse_qs, quote, unquote, urlsplit
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "incident_to_promtool.py"
DEMO = ROOT / "demo"
ENV_TOKEN = "test-environment-token"
INVALID_ENV_TOKEN = "invalid environment token"
FILE_TOKEN = "test-mounted-file.A0_-~+/=="


class PrometheusAuthIntegrationTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        self.config = self.workspace / "live incident.json"
        self.config.write_bytes((DEMO / "demo.json").read_bytes())
        self.matrix = json.loads((DEMO / "incident.matrix.json").read_text(encoding="utf-8"))
        self.token = self.workspace / "mounted credential.secret"
        self.token.write_bytes(FILE_TOKEN.encode("ascii") + b"\r\n")
        self.plan_rules = self.workspace / "planner rules.yml"
        self.plan_rules.write_text(
            "groups:\n- name: planner\n  rules:\n  - alert: CheckAvailability\n    expr: up\n",
            encoding="utf-8",
        )

    @contextmanager
    def server(self, respond=None, *, raw_status=None):
        requests = []
        matrix = self.matrix

        class Handler(BaseHTTPRequestHandler):
            def handle_api_request(self):
                target = urlsplit(self.path)
                form = target.query
                if self.command == "POST":
                    form = self.rfile.read(int(self.headers["Content-Length"])).decode("ascii")
                request = (self.command, target.path, parse_qs(form), self.headers.get("Authorization"))
                requests.append(request)
                if raw_status is not None:
                    self.wfile.write(raw_status)
                    return
                status, headers, payload = respond(request) if respond is not None else (200, {}, matrix)
                data = json.dumps(payload).encode("utf-8") if payload is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(data)

            do_GET = handle_api_request
            do_POST = handle_api_request

            def log_message(self, *_arguments):
                pass

        with HTTPServer(("127.0.0.1", 0), Handler) as server:
            worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            worker.start()
            try:
                host, port = server.server_address
                yield f"http://{host}:{port}", requests
            finally:
                server.shutdown()
                worker.join(timeout=5)

    def invoke(self, mode, filename=None, *, url=None, offline=False, token=None, environment_token=ENV_TOKEN):
        command = [sys.executable, CLI]
        if mode == "plan-capture":
            command.extend((mode, self.plan_rules, "--alertname", "CheckAvailability"))
        else:
            if mode != "generate":
                command.append(mode)
            command.append(self.config)
        if offline:
            command.extend(("--matrix", DEMO / "incident.matrix.json"))
        else:
            command.extend(("--prometheus-url", url))
        if token is not None:
            command.extend(("--bearer-token-file", token))
        if mode in ("generate", "bundle"):
            command.extend(("--rule-file", DEMO / "after.rules.yml"))
        if mode == "generate":
            command.extend(("--summary-format", "json"))
        if mode == "inspect":
            command.extend(("--format", "json"))
        output = self.workspace / filename if filename is not None else None
        if output is not None:
            command.extend(("--output", output))
        environment = {**os.environ, "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}
        if environment_token is None:
            environment.pop("PROMETHEUS_BEARER_TOKEN", None)
        else:
            environment["PROMETHEUS_BEARER_TOKEN"] = environment_token
        result = subprocess.run(
            command, cwd=self.workspace, env=environment, capture_output=True, text=True, timeout=30,
        )
        return result, output

    def assert_no_secret(self, content, *secrets):
        for secret in secrets:
            self.assertNotIn(secret, content)

    def test_all_capture_routes_use_the_file_override_without_persisting_credentials(self):
        mounted = self.workspace / "bearer-token-symlink"
        mounted.symlink_to(self.token.name)
        source = self.config.read_bytes()
        cases = (
            ("generate", "generated.test.yml"),
            ("bundle", "live capture.zip"),
            ("snapshot", "samples.json"),
            ("inspect", None),
        )
        with self.server() as (url, requests):
            for mode, filename in cases:
                with self.subTest(mode=mode):
                    fallback = INVALID_ENV_TOKEN if mode == "inspect" else ENV_TOKEN
                    result, output = self.invoke(mode, filename, url=f"{url}/prom", token=mounted, environment_token=fallback)

                    self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
                    self.assert_no_secret(result.stdout + result.stderr, FILE_TOKEN, fallback, mounted.name)
                    if output is None:
                        self.assertEqual(json.loads(result.stdout)["sample_count"], 21)
                    elif mode == "bundle":
                        with ZipFile(output) as bundle:
                            for member in bundle.namelist():
                                self.assert_no_secret(
                                    bundle.read(member), FILE_TOKEN.encode(), ENV_TOKEN.encode(), mounted.name.encode(),
                                )
                    else:
                        self.assert_no_secret(output.read_text(encoding="utf-8"), FILE_TOKEN, ENV_TOKEN, mounted.name)

        self.assertEqual(self.config.read_bytes(), source)
        self.assertEqual(len(requests), len(cases))
        for method, path, form, authorization in requests:
            self.assertEqual((method, path, authorization), ("GET", "/prom/api/v1/query", f"Bearer {FILE_TOKEN}"))
            self.assertEqual(form["query"], ['payment_http_requests_total{code="500"}[600001ms]'])

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML unavailable")
    def test_planner_posts_using_the_explicit_file_token(self):
        ast = {"status": "success", "data": {
            "type": "vectorSelector", "name": "up",
            "matchers": [{"name": "__name__", "type": "=", "value": "up"}],
            "offset": 0, "timestamp": None, "startOrEnd": None,
        }}
        with self.server(lambda _request: (200, {}, ast)) as (url, requests):
            result, _ = self.invoke("plan-capture", url=f"{url}/prom", token=self.token)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(json.loads(result.stdout)["selectors"], ["up"])
        self.assertEqual(requests, [("POST", "/prom/api/v1/parse_query", {"query": ["up"]}, f"Bearer {FILE_TOKEN}")])
        self.assert_no_secret(result.stdout + result.stderr, FILE_TOKEN, ENV_TOKEN)

    def test_token_is_read_once_with_multiple_queries_and_environment_fallback_still_works(self):
        data = json.loads(self.config.read_text(encoding="utf-8"))
        data["selectors"].append('payment_http_requests_total{code=~"200|500"}')
        self.config.write_text(json.dumps(data), encoding="utf-8")

        def rotate(_request):
            self.token.write_text("updated-file-token\n", encoding="ascii")
            return 200, {}, self.matrix

        with self.server(rotate) as (url, requests):
            file_result, _ = self.invoke("snapshot", "file.json", url=url, token=self.token)
            env_result, _ = self.invoke("snapshot", "environment.json", url=url)
            anonymous, _ = self.invoke("snapshot", "anonymous.json", url=url, environment_token=None)

        for result in (file_result, env_result, anonymous):
            self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertEqual([request[3] for request in requests], [
            f"Bearer {FILE_TOKEN}", f"Bearer {FILE_TOKEN}", f"Bearer {ENV_TOKEN}", f"Bearer {ENV_TOKEN}", None, None,
        ])

    def test_redirect_to_another_origin_does_not_forward_authorization(self):
        with self.server() as (destination, destination_requests):
            def redirect(_request):
                return 302, {"Location": f"{destination}/redirected-query"}, None

            with self.server(redirect) as (url, original_requests):
                result, output = self.invoke("snapshot", "redirected matrix.json", url=url, token=self.token)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertTrue(output.is_file())
        self.assertEqual(len(original_requests), 1)
        self.assertEqual(original_requests[0][3], f"Bearer {FILE_TOKEN}")
        self.assertEqual(destination_requests, [("GET", "/redirected-query", {}, None)])

    def test_http_error_redacts_echoed_file_and_environment_credentials(self):
        def echo(request):
            authorization = request[3]
            credential = authorization.removeprefix("Bearer ")
            escaped = quote(credential, safe="")
            return 401, {}, {"status": "error", "error": f"permission denied for {credential} ({authorization}, {escaped})"}

        with self.server(echo) as (url, requests):
            for filename, token in (("echoed-file.json", self.token), ("echoed-environment.json", None)):
                with self.subTest(token=token):
                    result, output = self.invoke("snapshot", filename, url=url, token=token)

                    self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
                    self.assertEqual(result.stdout, "")
                    self.assertIn("HTTP 401", result.stderr)
                    self.assertIn("permission denied", result.stderr)
                    self.assert_no_secret(result.stderr, FILE_TOKEN, quote(FILE_TOKEN, safe=""), ENV_TOKEN)
                    self.assertFalse(output.exists())
        self.assertEqual([request[3] for request in requests], [f"Bearer {FILE_TOKEN}", f"Bearer {ENV_TOKEN}"])

    def test_http_error_suppresses_detail_with_alternate_percent_encoding(self):
        canonical = quote(FILE_TOKEN, safe="")
        spellings = {
            "mixed": canonical.replace("%2F", "%2f"),
            "lowercase": re.sub(r"%[0-9A-F]{2}", lambda match: match.group().lower(), canonical),
        }
        for name, encoded in spellings.items():
            with self.subTest(spelling=name):
                self.assertNotEqual(encoded, canonical)
                self.assertEqual(unquote(encoded), FILE_TOKEN)
                response = {"status": "error", "error": f"sensitive denial detail: {encoded}"}
                with self.server(lambda _request: (401, {}, response)) as (url, requests):
                    result, output = self.invoke("snapshot", f"{name} echo.json", url=url, token=self.token)

                self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
                self.assertEqual(result.stdout, "")
                self.assertIn("HTTP 401", result.stderr)
                self.assert_no_secret(result.stderr, encoded, "sensitive denial detail")
                self.assertNotIn(FILE_TOKEN, unquote(result.stderr))
                self.assertFalse(output.exists())
                self.assertEqual([request[3] for request in requests], [f"Bearer {FILE_TOKEN}"])

    def test_malformed_http_status_is_reported_without_echoing_credentials(self):
        status = f"HTTP/1.1 {FILE_TOKEN} invalid status\r\n\r\n".encode("ascii")
        with self.server(raw_status=status) as (url, requests):
            result, output = self.invoke("snapshot", "invalid status.json", url=url, token=self.token)

        self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(result.stdout, "")
        self.assertIn("Prometheus request failed", result.stderr)
        self.assert_no_secret(result.stderr, FILE_TOKEN, "Traceback")
        self.assertFalse(output.exists())
        self.assertEqual([request[3] for request in requests], [f"Bearer {FILE_TOKEN}"])

    def test_bad_file_credentials_are_rejected_before_network_or_artifacts(self):
        malformed = {
            "empty": b"",
            "newline-only": b"\r\n",
            "bare-carriage-return": b"bad-token\r",
            "double-lf": b"bad-token\n\n",
            "double-crlf": b"bad-token\r\n\r\n",
            "multiline": b"bad-token-first\r\nbad-token-second\r\n",
            "embedded-space": b"bad-token words\n",
            "trailing-space": b"bad-token \n",
            "non-ascii": b"bad-token-\xff\n",
            "bad-padding": b"bad-token=interior\n",
        }
        invalid = {"missing": self.workspace / "missing-token.secret", "directory": self.workspace}
        for name, contents in malformed.items():
            token = self.workspace / f"{name}-token.secret"
            token.write_bytes(contents)
            invalid[name] = token
        with self.server() as (url, requests):
            for name, token in invalid.items():
                with self.subTest(case=name):
                    result, output = self.invoke("snapshot", f"{name}.json", url=url, token=token)

                    self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
                    self.assertEqual(result.stdout, "")
                    diagnostic = r"(?i)directory|token|bearer" if name == "directory" else r"(?i)token|bearer"
                    self.assertRegex(result.stderr, diagnostic)
                    self.assert_no_secret(result.stderr, "bad-token", ENV_TOKEN)
                    self.assertFalse(output.exists())
            for mode, filename, exit_code in (
                ("generate", "no token.test.yml", 1), ("bundle", "no token.zip", 1),
                ("inspect", None, 2), ("plan-capture", None, 2),
            ):
                with self.subTest(mode=mode):
                    result, output = self.invoke(mode, filename, url=url, token=invalid["missing"])

                    self.assertEqual(result.returncode, exit_code, f"{result.stdout}\n{result.stderr}")
                    self.assertEqual(result.stdout, "")
                    self.assertRegex(result.stderr, r"(?i)token|bearer")
                    if output is not None:
                        self.assertFalse(output.exists())

            result, output = self.invoke("snapshot", "bad environment.json", url=url, environment_token=INVALID_ENV_TOKEN)

            self.assertEqual(result.returncode, 1, f"{result.stdout}\n{result.stderr}")
            self.assertEqual(result.stdout, "")
            self.assertIn("PROMETHEUS_BEARER_TOKEN", result.stderr)
            self.assert_no_secret(result.stderr, INVALID_ENV_TOKEN)
            self.assertFalse(output.exists())
        self.assertEqual(requests, [])

    def test_offline_matrix_rejects_an_explicit_token_before_reading_it(self):
        token = self.workspace / "no-such-file.secret"
        for mode, filename in (
            ("generate", "rejected.test.yml"), ("bundle", "rejected.zip"),
            ("snapshot", "rejected.json"), ("inspect", None),
        ):
            with self.subTest(mode=mode):
                result, output = self.invoke(mode, filename, offline=True, token=token)

                self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
                self.assertEqual(result.stdout, "")
                self.assertIn("--bearer-token-file", result.stderr)
                self.assertRegex(result.stderr, r"(?i)matrix|prometheus-url")
                if output is not None:
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
