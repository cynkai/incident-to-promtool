"""Extract native Prometheus rule files from Kubernetes manifests."""


API_VERSION = "monitoring.coreos.com/v1"
RULE_GVK = (API_VERSION, "PrometheusRule")
RULE_LIST_GVK = (API_VERSION, "PrometheusRuleList")
LIST_GVK = ("v1", "List")


def rules_yaml_loader(yaml, *, preserve_scalars=False):
    class RulesLoader(yaml.SafeLoader):
        def __init__(self, stream):
            super().__init__(stream)
            self.flattened = set()
            self.flattening = set()

        def flatten_mapping(self, node):
            if node in self.flattened:
                return
            if node in self.flattening:
                raise yaml.constructor.ConstructorError(
                    None, None, "circular YAML merge", node.start_mark,
                )

            # Check the explicit keys before the SafeLoader expands YAML merges.
            # An explicit key may still override a key inherited from an anchor.
            keys = set()
            merge_key = object()
            for key_node, _ in node.value:
                if not isinstance(key_node, yaml.ScalarNode):
                    continue
                if key_node.tag == "tag:yaml.org,2002:merge":
                    key = merge_key
                elif key_node.tag == "tag:yaml.org,2002:value":
                    key = key_node.value
                else:
                    key = self.construct_object(key_node)
                if key in keys:
                    display = "<<" if key is merge_key else key
                    raise yaml.constructor.ConstructorError(
                        None, None, f"duplicate mapping key {display!r}", key_node.start_mark,
                    )
                keys.add(key)

            self.flattening.add(node)
            try:
                super().flatten_mapping(node)
            finally:
                self.flattening.remove(node)
            self.flattened.add(node)

    if preserve_scalars:
        # Prometheus reads rule expressions and names as scalar text, including YAML words like 'on'.
        RulesLoader.yaml_implicit_resolvers = {
            character: [(tag, pattern) for tag, pattern in resolvers if tag == "tag:yaml.org,2002:merge"]
            for character, resolvers in RulesLoader.yaml_implicit_resolvers.items()
        }
    return RulesLoader


def _gvk(resource, location):
    version = resource.get("apiVersion")
    kind = resource.get("kind")
    if kind in ("PrometheusRule", "PrometheusRuleList") and version != API_VERSION:
        raise ValueError(f"{location}: {kind}.apiVersion must be {API_VERSION}, got {version!r}")
    return version, kind


def _resources(document, location):
    if not isinstance(document, dict):
        return
    gvk = _gvk(document, location)
    if gvk == RULE_GVK:
        yield document, location
        return
    if gvk not in (LIST_GVK, RULE_LIST_GVK):
        return

    items = document.get("items")
    if not isinstance(items, list):
        raise ValueError(f"{location}: {gvk[1]}.items must be a list")
    for index, item in enumerate(items, start=1):
        item_location = f"{location}, item {index}"
        if not isinstance(item, dict):
            raise ValueError(f"{item_location}: expected a Kubernetes resource mapping")
        if gvk == RULE_LIST_GVK:
            item_gvk = (item.get("apiVersion", API_VERSION), item.get("kind", "PrometheusRule"))
            if item_gvk != RULE_GVK:
                raise ValueError(f"{item_location}: PrometheusRuleList items must be {API_VERSION} PrometheusRules")
        else:
            item_gvk = _gvk(item, item_location)
        if item_gvk == RULE_GVK:
            yield item, item_location


def _rule_groups(resource, location):
    metadata = resource.get("metadata")
    name = metadata.get("name") if isinstance(metadata, dict) else None
    if isinstance(name, str) and name:
        location = f"{location} (PrometheusRule {name!r})"

    spec = resource.get("spec", {})
    groups = spec.get("groups", []) if isinstance(spec, dict) else None
    if not isinstance(groups, list):
        raise ValueError(f"{location}: PrometheusRule.spec.groups must be a list")
    native = []
    for index, group in enumerate(groups, start=1):
        group_location = f"{location}: PrometheusRule.spec.groups item {index}"
        if not isinstance(group, dict):
            raise ValueError(f"{group_location} must be a mapping")
        group_name = group.get("name")
        if not isinstance(group_name, str) or not group_name.strip():
            raise ValueError(f"{group_location} requires a nonempty name")
        rules = group.get("rules")
        if rules is not None and (not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules)):
            raise ValueError(f"{group_location}.rules must be a list of mappings")
        # The Operator ignores this Thanos Ruler setting for Prometheus.
        native.append({key: value for key, value in group.items() if key != "partial_response_strategy"})
    return native


def convert_manifests(sources: list[tuple[str, bytes]]) -> list[bytes]:
    """Return one native Prometheus rule-file document per PrometheusRule."""
    try:
        import yaml
    except ImportError as exc:
        raise ValueError(
            "Kubernetes manifest conversion requires PyYAML 6. "
            "Install it with: python3 -m pip install 'PyYAML>=6,<7'"
        ) from exc

    loader = rules_yaml_loader(yaml)
    rule_files = []
    found_groups = False
    for source, content in sources:
        try:
            documents = list(yaml.load_all(content, Loader=loader))
        except (yaml.YAMLError, ValueError, OverflowError, RecursionError) as exc:
            raise ValueError(f"{source}: invalid Kubernetes YAML: {exc}") from exc

        for index, document in enumerate(documents, start=1):
            for resource, location in _resources(document, f"{source}, document {index}"):
                groups = _rule_groups(resource, location)
                try:
                    native = yaml.safe_dump({"groups": groups}, sort_keys=False, allow_unicode=True)
                except (yaml.YAMLError, RecursionError) as exc:
                    raise ValueError(f"{location}: could not write native Prometheus rule YAML: {exc}") from exc
                rule_files.append(native.encode("utf-8"))
                found_groups = found_groups or bool(groups)

    if not found_groups:
        names = ", ".join(source for source, _ in sources) or "the supplied manifests"
        raise ValueError(f"{names}: no {API_VERSION} PrometheusRules with nonempty spec.groups found")
    return rule_files
