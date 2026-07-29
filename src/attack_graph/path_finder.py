from __future__ import annotations

from typing import Any

import networkx as nx


def get_primary_targets(
    graph: nx.MultiDiGraph,
) -> list[str]:
    """Return asset nodes marked as primary targets."""

    return [
        node_id
        for node_id, attributes in graph.nodes(data=True)
        if (
            attributes.get("node_type") == "asset"
            and attributes.get("is_primary_target") is True
        )
    ]


def edge_has_type(
    graph: nx.MultiDiGraph,
    source: str,
    target: str,
    expected_edge_type: str,
) -> bool:
    """Check whether two nodes have the expected edge type."""

    edge_data = graph.get_edge_data(source, target, default={})

    return any(
        attributes.get("edge_type") == expected_edge_type
        for attributes in edge_data.values()
    )


def is_valid_attack_path(
    graph: nx.MultiDiGraph,
    path: list[str],
) -> bool:
    """
    Validate exploit-based and access-condition-based transitions.

    Supported transitions:

    attacker -> service
    asset -> service
    service -> vulnerability
    vulnerability -> asset
    asset -> access condition
    access condition -> asset
    """

    if len(path) < 4:
        return False

    first_type = graph.nodes[path[0]].get("node_type")
    last_type = graph.nodes[path[-1]].get("node_type")

    if first_type != "attacker":
        return False

    if last_type != "asset":
        return False

    allowed_transitions = {
        ("attacker", "service"): "can_reach",
        ("asset", "service"): "can_reach",
        ("service", "vulnerability"): "has_vulnerability",
        ("vulnerability", "asset"): "compromises",
        (
            "asset",
            "access_condition",
        ): "requires_access_condition",
        (
            "access_condition",
            "asset",
        ): "grants_access",
    }

    vulnerability_found = False

    for source, target in zip(path, path[1:]):
        source_type = graph.nodes[source].get("node_type", "")
        target_type = graph.nodes[target].get("node_type", "")

        transition = (source_type, target_type)

        expected_edge_type = allowed_transitions.get(transition)

        if expected_edge_type is None:
            return False

        if not edge_has_type(
            graph,
            source,
            target,
            expected_edge_type,
        ):
            return False

        if target_type == "vulnerability":
            vulnerability_found = True

    return vulnerability_found


def summarize_path(
    graph: nx.MultiDiGraph,
    path: list[str],
    path_number: int,
) -> dict[str, Any]:
    """Create a readable summary of one attack path."""

    labels: list[str] = []
    vulnerabilities: list[str] = []
    access_conditions: list[str] = []
    compromised_assets: list[str] = []

    maximum_cvss = 0.0
    maximum_epss = 0.0
    kev_present = False

    scenario_assumption_count = 0
    observed_condition_count = 0

    for node_id in path:
        attributes = graph.nodes[node_id]
        node_type = attributes.get("node_type", "")

        label = str(attributes.get("label", node_id))
        labels.append(label)

        if node_type == "vulnerability":
            identifier = (
                attributes.get("cve_id")
                or attributes.get("label")
                or node_id
            )

            vulnerabilities.append(str(identifier))

            openvas_cvss = float(
                attributes.get("openvas_cvss") or 0.0
            )

            nvd_cvss = float(
                attributes.get("nvd_cvss") or 0.0
            )

            maximum_cvss = max(
                maximum_cvss,
                openvas_cvss,
                nvd_cvss,
            )

            maximum_epss = max(
                maximum_epss,
                float(attributes.get("epss") or 0.0),
            )

            if attributes.get("kev") is True:
                kev_present = True

        elif node_type == "access_condition":
            condition_type = str(
                attributes.get("condition_type", label)
            )

            evidence_type = str(
                attributes.get("evidence_type", "")
            )

            confidence = str(
                attributes.get("confidence", "")
            )

            access_conditions.append(
                f"{condition_type} "
                f"[{evidence_type}, {confidence}]"
            )

            if evidence_type == "scenario_assumption":
                scenario_assumption_count += 1
            else:
                observed_condition_count += 1

        elif node_type == "asset":
            compromised_assets.append(label)

    return {
        "path_id": f"PATH-{path_number:04d}",
        "node_ids": path,
        "labels": labels,
        "hop_count": len(path) - 1,
        "exploit_stage_count": len(vulnerabilities),
        "access_condition_count": len(access_conditions),
        "vulnerabilities": vulnerabilities,
        "access_conditions": access_conditions,
        "compromised_assets": compromised_assets,
        "maximum_cvss": maximum_cvss,
        "maximum_epss": maximum_epss,
        "kev_present": kev_present,
        "scenario_assumption_count": scenario_assumption_count,
        "observed_condition_count": observed_condition_count,
        "final_target": labels[-1],
    }


def find_attack_paths(
    graph: nx.MultiDiGraph,
    source: str = "ATTACKER",
    targets: list[str] | None = None,
    cutoff: int = 12,
    maximum_paths: int = 5000,
) -> list[dict[str, Any]]:
    """Find valid paths from the attacker to primary targets."""

    if source not in graph:
        raise ValueError(
            f"Source node does not exist: {source}"
        )

    if targets is None:
        targets = get_primary_targets(graph)

    if not targets:
        raise ValueError(
            "No primary target asset was found."
        )

    simple_graph = nx.DiGraph()
    simple_graph.add_nodes_from(graph.nodes(data=True))

    for source_node, target_node in graph.edges():
        simple_graph.add_edge(source_node, target_node)

    discovered_paths: list[list[str]] = []

    for target in targets:
        if target not in simple_graph:
            continue

        if not nx.has_path(simple_graph, source, target):
            continue

        for path in nx.all_simple_paths(
            simple_graph,
            source=source,
            target=target,
            cutoff=cutoff,
        ):
            if not is_valid_attack_path(graph, path):
                continue

            discovered_paths.append(path)

            if len(discovered_paths) >= maximum_paths:
                break

        if len(discovered_paths) >= maximum_paths:
            break

    discovered_paths.sort(
        key=lambda discovered_path: (
            len(discovered_path),
            tuple(discovered_path),
        )
    )

    return [
        summarize_path(
            graph,
            path,
            path_number=index,
        )
        for index, path in enumerate(
            discovered_paths,
            start=1,
        )
    ]