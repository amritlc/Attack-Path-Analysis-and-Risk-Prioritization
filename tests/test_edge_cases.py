import networkx as nx


def test_disconnected_component_not_in_paths():
    graph = nx.DiGraph()

    graph.add_edges_from([
        ("attacker", "web"),
        ("web", "database"),
    ])

    graph.add_node("isolated")

    paths = list(
        nx.all_simple_paths(
            graph,
            "attacker",
            "database",
        )
    )

    assert paths == [
        ["attacker", "web", "database"]
    ]

    assert all(
        "isolated" not in path
        for path in paths
    )


def test_repeated_vulnerability_does_not_duplicate_path():
    graph = nx.DiGraph()

    graph.add_edge(
        "attacker",
        "server",
        step_type="candidate_compromise",
    )

    graph.add_edge(
        "server",
        "database",
        step_type="target_reach",
    )

    vulnerabilities = [
        "CVE-A",
        "CVE-A",
        "CVE-B",
    ]

    unique_vulnerabilities = set(
        vulnerabilities
    )

    paths = list(
        nx.all_simple_paths(
            graph,
            "attacker",
            "database",
        )
    )

    assert len(unique_vulnerabilities) == 2
    assert len(paths) == 1