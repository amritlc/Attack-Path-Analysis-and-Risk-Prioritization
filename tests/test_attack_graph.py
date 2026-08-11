from pathlib import Path
import pandas as pd
import networkx as nx

BASE = Path("data/processed/lab")
GRAPH = BASE / "graph"

graph = nx.read_graphml(GRAPH / "attack_graph.graphml")
nodes = pd.read_csv(GRAPH / "graph_nodes.csv")
edges = pd.read_csv(GRAPH / "graph_edges.csv")


def test_graph_is_directed():
    # A directed attack graph is expected.
    assert graph.is_directed()


def test_graph_node_counts():
    # Expected node counts are checked.
    assert (nodes["type"] == "asset").sum() == 5
    assert (nodes["type"] == "service").sum() == 42
    assert (nodes["type"] == "vulnerability").sum() == 154
    assert len(nodes) == 201


def test_graph_edge_counts():
    # Expected relationship counts are checked.
    counts = edges["relation"].value_counts()

    assert counts["hosts_service"] == 42
    assert counts["can_reach"] == 13
    assert counts["has_vulnerability"] == 198
    assert counts["affects"] == 154
    assert len(edges) == 407


def test_services_have_hosts():
    # Every service must belong to an asset.
    services = set(nodes[nodes["type"] == "service"]["node"])

    hosted = set(
        edges[edges["relation"] == "hosts_service"]["target"]
    )

    assert services == hosted


def test_vulnerabilities_are_linked():
    # Every vulnerability must be linked in the graph.
    vulnerabilities = set(
        nodes[nodes["type"] == "vulnerability"]["node"]
    )

    has_vuln = set(
        edges[edges["relation"] == "has_vulnerability"]["target"]
    )

    affects = set(
        edges[edges["relation"] == "affects"]["source"]
    )

    assert vulnerabilities == has_vuln
    assert vulnerabilities == affects


def test_attacker_exists():
    # One attacker must be defined.
    assert (nodes["role"] == "attacker").sum() == 1


def test_target_exists():
    # One critical target must be defined.
    assert nodes["target"].eq(True).sum() == 1


def test_database_connectivity():
    # Verified attacker-to-database access is checked.
    source = "asset:192.168.100.6"
    target = "service:192.168.100.5:3306:tcp"

    match = edges[
        (edges["source"] == source) &
        (edges["target"] == target) &
        (edges["relation"] == "can_reach")
    ]

    assert len(match) == 1