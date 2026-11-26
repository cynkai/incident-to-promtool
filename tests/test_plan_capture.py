from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from textwrap import dedent
from threading import Thread
import unittest
from urllib.parse import parse_qs


CLI = Path(__file__).resolve().parents[1] / "incident_to_promtool.py"


def selector(name, *matchers, **modifiers):
    if name:
        matchers += (("__name__", "=", name),)
    return {
        "type": "matrixSelector" if "range" in modifiers else "vectorSelector",
        "name": name,
        "matchers": [{"name": label, "type": operator, "value": value} for label, operator, value in matchers],
        "offset": 0,
        "timestamp": None,
        "startOrEnd": None,
        **modifiers,
    }


def binary(operator, left, right):
    return {"type": "binaryExpr", "op": operator, "lhs": left, "rhs": right, "bool": False, "matching": None}


def number(value):
    return {"type": "numberLiteral", "val": str(value)}


def call(name, argument_type, argument):
    return {
        "type": "call",
        "func": {"name": name, "argTypes": [argument_type], "returnType": "vector", "variadic": 0},
        "args": [argument],
    }


@unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML unavailable")
class PlanCaptureTests(unittest.TestCase):
    def setUp(self):
        workspace = TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)

    def write_rules(self, name, rules):
        path = self.workspace / name
        path.write_text(dedent(rules), encoding="utf-8")
        return path

    def single_alert(self, expression):
        return self.write_rules("one.rules.yml", f"""
            groups:
              - name: plans
                rules:
                  - alert: Check
                    expr: {json.dumps(expression)}
        """)

    def plan(self, files, alertnames, responses):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode("utf-8"))
                requests.append((self.command, self.path, form, self.headers.get("Authorization")))
                query, = form.get("query", [""])
                response = responses.get(query)
                if response is None:
                    status, payload = 404, {"status": "error", "error": f"unexpected parser query: {query}"}
                elif isinstance(response, tuple):
                    status, payload = response
                else:
                    status, payload = 200, {"status": "success", "data": response}
                document = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(document)))
                self.end_headers()
                self.wfile.write(document)

            def log_message(self, *_arguments):
                pass

        with HTTPServer(("127.0.0.1", 0), Handler) as server:
            worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            worker.start()
            try:
                host, port = server.server_address
                env = {**os.environ, "NO_PROXY": host, "no_proxy": host, "PROMETHEUS_BEARER_TOKEN": "local-plan-token"}
                command = [sys.executable, CLI, "plan-capture", *files, "--prometheus-url", f"http://{host}:{port}/prom"]
                for name in alertnames:
                    command.extend(("--alertname", name))
                result = subprocess.run(
                    command, cwd=self.workspace, env=env, capture_output=True, text=True, timeout=30,
                )
            finally:
                server.shutdown()
                worker.join(timeout=5)
        return result, requests

    def assert_plan_failed(self, result, diagnostic):
        self.assertEqual(result.returncode, 2, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(result.stdout, "")
        self.assertRegex(result.stderr, diagnostic)

    def test_matches_prometheus_first_document_rule_loading(self):
        path = self.write_rules("multi-document.rules.yml", """
            groups:
              - name: loaded
                rules: [{alert: Check, expr: up}]
            ---
            groups:
              - name: ignored
                rules: [{alert: Check, expr: ignored_metric}]
        """)
        result, requests = self.plan([path], ["Check"], {"up": selector("up")})

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(json.loads(result.stdout)["selectors"], ["up"])
        self.assertEqual([form for _, _, form, _ in requests], [{"query": ["up"]}])

    def test_follows_every_recording_rule_producer_and_unions_matching_alerts(self):
        primary = self.write_rules("first rules.yml", r"""
            groups:
              - name: primary
                rules:
                  - alert: Errors
                    expr: app:errors{cluster="prod"} > 1
                  - alert: Availability
                    expr: '{__name__="up",job="api"} == 0'
                  - alert: Unselected
                    expr: ignore_me
                  - record: app:errors
                    expr: sum(rate(requests_total{z="x",a!="y"}[2m] offset 1m @ 30))
                  - record: app:smoothed
                    expr: latency_seconds{service="internal",route="a\"b\\c"}
        """)
        secondary = self.write_rules("second.rules.yml", """
            groups:
              - name: secondary
                rules:
                  - alert: Errors
                    expr: ready or up{job="api"}
                  - record: app:errors
                    expr: app:smoothed{service="consumer"} + ({__name__="fallback_seconds",job="api"})
        """)
        responses = {
            'app:errors{cluster="prod"} > 1': binary(">", selector("app:errors", ("cluster", "=", "prod")), number(1)),
            '{__name__="up",job="api"} == 0': binary(
                "==", selector("", ("__name__", "=", "up"), ("job", "=", "api")), number(0),
            ),
            'sum(rate(requests_total{z="x",a!="y"}[2m] offset 1m @ 30))': {
                "type": "aggregation", "op": "sum", "grouping": [], "without": False, "param": None,
                "expr": call("rate", "matrix", selector(
                    "requests_total", ("z", "=", "x"), ("a", "!=", "y"),
                    range=120_000, offset=60_000, timestamp=30_000,
                )),
            },
            r'latency_seconds{service="internal",route="a\"b\\c"}': selector(
                "latency_seconds", ("service", "=", "internal"), ("route", "=", r'a"b\c'),
            ),
            'ready or up{job="api"}': binary("or", selector("ready"), selector("up", ("job", "=", "api"))),
            'app:smoothed{service="consumer"} + ({__name__="fallback_seconds",job="api"})': binary(
                "+", selector("app:smoothed", ("service", "=", "consumer")),
                {"type": "parenExpr", "expr": selector("", ("__name__", "=", "fallback_seconds"), ("job", "=", "api"))},
            ),
        }

        result, requests = self.plan([primary, secondary], ["Errors", "Availability", "Errors"], responses)

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(json.loads(result.stdout), {
            "schema_version": 1,
            "alertnames": ["Availability", "Errors"],
            "recording_rules": ["app:errors", "app:smoothed"],
            "selectors": [
                r'latency_seconds{route="a\"b\\c",service="internal"}',
                "ready",
                'requests_total{a!="y",z="x"}',
                'up{job="api"}',
                '{__name__="fallback_seconds",job="api"}',
            ],
        })
        for method, path, form, authorization in requests:
            self.assertEqual((method, path, authorization), ("POST", "/prom/api/v1/parse_query", "Bearer local-plan-token"))
            self.assertEqual(set(form), {"query"})
            self.assertEqual(len(form["query"]), 1)
        self.assertEqual({form["query"][0] for _, _, form, _ in requests}, set(responses))

    def test_unknown_alert_stops_before_contacting_parser(self):
        path = self.single_alert("up")

        result, requests = self.plan([path], ["Check", "Missing"], {"up": selector("up")})

        self.assert_plan_failed(result, r"(?i)missing")
        self.assertEqual(requests, [])

    def test_rejects_recording_rule_cycle(self):
        path = self.write_rules("cycle.rules.yml", """
            groups:
              - name: cycles
                rules:
                  - alert: Check
                    expr: app:first
                  - record: app:first
                    expr: app:second
                  - record: app:second
                    expr: app:first
        """)

        result, _ = self.plan(
            [path], ["Check"], {"app:first": selector("app:first"), "app:second": selector("app:second")},
        )

        self.assert_plan_failed(result, r"(?i)cycl")

    def test_constant_expression_produces_an_empty_capture_plan(self):
        expression = "vector(1)"
        path = self.single_alert(expression)

        result, _ = self.plan([path], ["Check"], {expression: call("vector", "scalar", number(1))})

        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(json.loads(result.stdout), {
            "schema_version": 1, "alertnames": ["Check"], "recording_rules": [], "selectors": [],
        })

    def test_rejects_ambiguous_or_implicit_metric_dependencies(self):
        unsupported = (
            ('{job="api"}', selector("", ("job", "=", "api")), r"(?i)metric|__name__"),
            ('{__name__=~"up|ready"}', selector("", ("__name__", "=~", "up|ready")), r"(?i)metric|__name__"),
            ("info(up)", call("info", "vector", selector("up")), r"(?i)info|implicit"),
        )
        for expression, parsed, diagnostic in unsupported:
            with self.subTest(expression=expression):
                result, _ = self.plan([self.single_alert(expression)], ["Check"], {expression: parsed})

                self.assert_plan_failed(result, diagnostic)

    def test_rejects_http_errors_and_unrecognized_parser_nodes(self):
        path = self.single_alert("up")
        for response, diagnostic in (
            ((400, {"status": "error", "errorType": "bad_data", "error": "malformed PromQL"}), r"(?i)400|malformed"),
            ({"type": "futureNode"}, r"(?i)futurenode|node type|unsupported"),
        ):
            with self.subTest(response=response):
                result, requests = self.plan([path], ["Check"], {"up": response})

                self.assert_plan_failed(result, diagnostic)
                self.assertEqual(len(requests), 1)


if __name__ == "__main__":
    unittest.main()
