from __future__ import annotations

from typing import Any

import networkx as nx


def get_primary_targets(
    graph: nx.MultiDiGraph,
) -> list[str]:
    """Return assets marked as primary targets."""

    return [
        node_id
        for node_id, attributes in graph.nodes(data=True)
        if (
            attributes.get("node_type") == "asset"
            and attributes.get("is_primary_target") is True
        )
    ]


def is_valid_attack_path(
    graph: nx.MultiDiGraph,
    path: list[str],
) -> bool:
    """
    Validate the expected attack-path structure:

    Attacker
      -> Service
      -> Vulnerability
      -> Asset
      -> Service
      -> Vulnerability
      -> Asset
    """

    if len(path) < 4:
        return False

    node_types = [
        graph.nodes[node].get("node_type", "")
        for node in path
    ]

    if node_types[0] != "attacker":
        return False

    if node_types[-1] != "asset":
        return False

    expected_cycle = {
        1: "service",
        2: "vulnerability",
        0: "asset",
    }

    for index in range(1, len(node_types)):
        expected_type = expected_cycle[index % 3]

        if node_types[index] != expected_type:
            return False

    return True


def summarize_path(
    graph: nx.MultiDiGraph,
    path: list[str],
    path_number: int,
) -> dict[str, Any]:
    """Create a readable summary of one attack path."""

    labels: list[str] = []
    vulnerabilities: list[str] = []
    target_assets: list[str] = []

    maximum_cvss = 0.0
    maximum_epss = 0.0
    kev_present = False

    for node_id in path:
        attributes = graph.nodes[node_id]
        node_type = attributes.get("node_type", "")

        labels.append(
            str(attributes.get("label", node_id))
        )

        if node_type == "vulnerability":
            identifier = (
                attributes.get("cve_id")
                or attributes.get("label")
                or node_id
            )

            vulnerabilities.append(str(identifier))

            maximum_cvss = max(
                maximum_cvss,
                float(
                    attributes.get("nvd_cvss")
                    or attributes.get("openvas_cvss")
                    or 0.0
                ),
            )

            maximum_epss = max(
                maximum_epss,
                float(attributes.get("epss") or 0.0),
            )

            if attributes.get("kev") is True:
                kev_present = True

        if node_type == "asset":
            target_assets.append(
                str(attributes.get("label", node_id))
            )

    return {
        "path_id": f"PATH-{path_number:04d}",
        "node_ids": path,
        "labels": labels,
        "hop_count": len(path) - 1,
        "exploit_stage_count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
        "compromised_assets": target_assets,
        "maximum_cvss": maximum_cvss,
        "maximum_epss": maximum_epss,
        "kev_present": kev_present,
        "final_target": labels[-1],
    }


def find_attack_paths(
    graph: nx.MultiDiGraph,
    source: str = "ATTACKER",
    targets: list[str] | None = None,
    cutoff: int = 12,
    maximum_paths: int = 5000,
) -> list[dict[str, Any]]:
    """
    Find complete simple attack paths from the attacker
    to the primary target asset.
    """

    if source not in graph:
        raise ValueError(
            f"Source node does not exist: {source}"
        )

    if targets is None:
        targets = get_primary_targets(graph)

    if not targets:
        raise ValueError(
            "No primary target asset was found in the graph."
        )

    # Parallel edges are not needed for simple-path discovery.
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
        key=lambda path: (
            len(path),
            tuple(path),
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