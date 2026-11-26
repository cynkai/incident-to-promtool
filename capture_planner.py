"""Plan direct metric captures from a Prometheus rule dependency graph."""

from collections import defaultdict
from contextlib import closing
from dataclasses import dataclass
from graphlib import CycleError, TopologicalSorter
import json
import re


METRIC_NAME = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
LABEL_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")
MATCHER_TYPES = {"=", "!=", "=~", "!~"}
GENERATED_METRICS = {"ALERTS", "ALERTS_FOR_STATE"}


@dataclass(frozen=True)
class Rule:
    location: str
    expression: object


def _read_rules(sources):
    try:
        import yaml
    except ImportError as exc:
        raise ValueError(
            "Capture planning requires PyYAML 6. Install the planner extra "
            "with python3 -m pip install 'incident-to-promtool[planner]' "
            "or install 'PyYAML>=6,<7' for a source checkout."
        ) from exc

    from kubernetes_rules import rules_yaml_loader

    loader = rules_yaml_loader(yaml, preserve_scalars=True)
    alerts, recordings = defaultdict(list), defaultdict(list)
    for source, content in sources:
        try:
            # Prometheus loads the first YAML document from each rule file.
            with closing(yaml.load_all(content, Loader=loader)) as documents:
                document = next(documents, None)
        except (yaml.YAMLError, ValueError, OverflowError, RecursionError) as exc:
            raise ValueError(f"{source}: invalid Prometheus rule YAML: {exc}") from exc
        if document in (None, "", {}):
            continue
        groups = document.get("groups") if isinstance(document, dict) else None
        if not isinstance(groups, list):
            raise ValueError(f"{source}: expected a Prometheus rule document with a groups list")
        for group_index, group in enumerate(groups, start=1):
            group_location = f"{source}, group {group_index}"
            rules = group.get("rules", []) if isinstance(group, dict) else None
            if not isinstance(rules, list):
                raise ValueError(f"{group_location}: expected a rule group with a rules list")
            for rule_index, rule in enumerate(rules, start=1):
                rule_location = f"{group_location}, rule {rule_index}"
                if not isinstance(rule, dict) or ("alert" in rule) == ("record" in rule):
                    raise ValueError(f"{rule_location}: a rule must have exactly one alert or record name")
                kind = "alert" if "alert" in rule else "record"
                name = rule[kind]
                if not isinstance(name, str) or not name.strip():
                    raise ValueError(f"{rule_location}: {kind} must have a nonempty name")
                index = alerts if kind == "alert" else recordings
                index[name].append(Rule(f"{rule_location} ({kind} {name!r})", rule.get("expr")))
    return alerts, recordings


def _metric_selector(node):
    prefix = node.get("name")
    raw_matchers = node.get("matchers")
    if not isinstance(prefix, str) or not isinstance(raw_matchers, list):
        raise ValueError("malformed PromQL AST selector: expected a metric name and matchers list")

    names = {prefix} if prefix else set()
    matchers = []
    for matcher in raw_matchers:
        if not isinstance(matcher, dict):
            raise ValueError("malformed PromQL AST selector matcher")
        label, operator, value = matcher.get("name"), matcher.get("type"), matcher.get("value")
        if not isinstance(label, str) or not isinstance(operator, str) or not isinstance(value, str):
            raise ValueError("malformed PromQL AST selector matcher: expected a name, operator and string value")
        if not LABEL_NAME.fullmatch(label):
            raise ValueError(f"unsupported Prometheus label name {label!r} in selector")
        if operator not in MATCHER_TYPES:
            raise ValueError(f"unsupported PromQL selector matcher operator {operator!r}")
        if label == "__name__" and operator == "=":
            names.add(value)
        else:
            matchers.append((label, operator, value))

    if not names:
        raise ValueError("dynamic PromQL selector requires a literal metric name or an exact __name__ matcher")
    if len(names) != 1:
        raise ValueError(f"ambiguous PromQL selector has multiple exact metric names: {', '.join(sorted(names))}")
    metric, = names
    if not METRIC_NAME.fullmatch(metric):
        raise ValueError(f"unsupported Prometheus metric name {metric!r} in selector")
    if metric in GENERATED_METRICS:
        raise ValueError(f"generated metric {metric} cannot be planned as a raw capture")

    # An actual prefixed selector can be rendered without its synthetic __name__
    # matcher. Anonymous exact-name selectors can use names reserved as keywords.
    prefixed = bool(prefix) and all(label != "__name__" for label, _, _ in matchers)
    return metric, tuple(sorted(set(matchers))), prefixed


def _expression_selectors(ast):
    pending = [ast]
    while pending:
        node = pending.pop()
        kind = node.get("type") if isinstance(node, dict) else None
        if not isinstance(kind, str):
            raise ValueError("malformed PromQL AST: expected a typed expression node")
        if kind in ("vectorSelector", "matrixSelector"):
            yield _metric_selector(node)
        elif kind in ("numberLiteral", "stringLiteral"):
            if not isinstance(node.get("val"), str):
                raise ValueError(f"malformed PromQL AST {kind}: expected a string value")
        elif kind in ("subquery", "parenExpr", "unaryExpr"):
            pending.append(node.get("expr"))
        elif kind == "aggregation":
            if "param" not in node:
                raise ValueError("malformed PromQL AST aggregation: expected a parameter field")
            if node["param"] is not None:
                pending.append(node["param"])
            pending.append(node.get("expr"))
        elif kind == "binaryExpr":
            pending.extend((node.get("rhs"), node.get("lhs")))
        elif kind == "call":
            function = node.get("func")
            name = function.get("name") if isinstance(function, dict) else None
            arguments = node.get("args")
            if not isinstance(name, str) or not name or not isinstance(arguments, list):
                raise ValueError("malformed PromQL AST call: expected a function name and arguments list")
            if name == "info":
                raise ValueError("info() may read implicit series and is not supported for capture planning")
            pending.extend(reversed(arguments))
        else:
            raise ValueError(f"unsupported PromQL AST node type {kind!r}")


def _format_selector(metric, matchers, prefixed):
    if not prefixed:
        matchers = sorted((*matchers, ("__name__", "=", metric)))
    if not matchers:
        return metric
    body = ",".join(f"{label}{op}{json.dumps(value, ensure_ascii=False)}" for label, op, value in matchers)
    return (metric if prefixed else "") + "{" + body + "}"


def plan_capture(sources: list[tuple[str, bytes]], alertnames, parse_expression) -> dict:
    """Find raw selectors needed by the selected alerts and their recording rules."""
    alertnames = list(alertnames)
    if any(not isinstance(name, str) or not name.strip() for name in alertnames):
        raise ValueError("alert names must be nonempty strings")
    names = sorted(set(alertnames))
    alerts, recordings = _read_rules(sources)
    missing = [name for name in names if name not in alerts]
    if missing:
        raise ValueError(f"alert rules not found: {', '.join(missing)}")

    selectors = {}
    parsed = {}

    def dependencies(rules):
        recording_names = set()
        for rule in rules:
            expression = rule.expression
            if not isinstance(expression, str) or not expression.strip():
                raise ValueError(f"{rule.location}: requires a nonempty PromQL expr")
            if expression not in parsed:
                try:
                    parsed[expression] = tuple(_expression_selectors(parse_expression(expression)))
                except ValueError as exc:
                    raise ValueError(f"{rule.location}: {exc}") from exc
            for metric, matchers, prefixed in parsed[expression]:
                if metric in recordings:
                    recording_names.add(metric)
                else:
                    key = (metric, matchers)
                    selectors[key] = selectors.get(key, False) or prefixed
        return recording_names

    graph = {}
    pending = sorted(dependencies(rule for name in names for rule in alerts[name]), reverse=True)
    while pending:
        metric = pending.pop()
        if metric in graph:
            continue
        graph[metric] = sorted(dependencies(recordings[metric]))
        pending.extend(reversed(graph[metric]))
    try:
        TopologicalSorter(graph).prepare()
    except CycleError as exc:
        raise ValueError(f"recording rule dependency cycle: {' -> '.join(exc.args[1])}") from exc

    return {
        "schema_version": 1,
        "alertnames": names,
        "recording_rules": sorted(graph),
        "selectors": sorted(_format_selector(metric, matchers, prefixed) for (metric, matchers), prefixed in selectors.items()),
    }
