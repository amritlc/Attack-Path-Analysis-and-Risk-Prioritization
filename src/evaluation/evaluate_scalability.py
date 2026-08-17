from pathlib import Path
import time
import tracemalloc

import networkx as nx
import pandas as pd


OUT = Path("data/processed/lab/evaluation")
OUT.mkdir(parents=True, exist_ok=True)

SCENARIOS = [
    ("S1", 5, 5),
    ("S2", 10, 10),
    ("S3", 20, 20),
    ("S4", 40, 40),
    ("S5", 80, 80),
]

REPEATS = 5


def build_graph(host_count, vulns_per_host):
    graph = nx.DiGraph()

    attacker = "asset:attacker"
    target = "asset:target"

    graph.add_node(attacker, type="asset")
    graph.add_node(target, type="asset")

    intermediates = []

    # Intermediate assets and vulnerability evidence are added.
    for index in range(host_count - 2):
        asset = f"asset:host{index + 1}"
        service = f"service:host{index + 1}:80:tcp"

        intermediates.append(asset)

        graph.add_node(asset, type="asset")
        graph.add_node(service, type="service")

        graph.add_edge(
            asset,
            service,
            relation="hosts_service",
        )

        for number in range(vulns_per_host):
            vuln = (
                f"vuln:host{index + 1}:"
                f"SYN-{number + 1}"
            )

            graph.add_node(
                vuln,
                type="vulnerability",
            )

            graph.add_edge(
                service,
                vuln,
                relation="has_vulnerability",
            )

            graph.add_edge(
                vuln,
                asset,
                relation="affects",
            )

    return graph, attacker, target, intermediates


def build_attack_graph(
    attacker,
    target,
    intermediates,
):
    attack = nx.DiGraph()

    attack.add_node(attacker)
    attack.add_node(target)

    # Attacker reachability is added.
    for asset in intermediates:
        attack.add_edge(
            attacker,
            asset,
            step_type="candidate_compromise",
        )

        attack.add_edge(
            asset,
            target,
            step_type="target_reach",
        )

    # Sequential lateral movement is added.
    for source, destination in zip(
        intermediates[:-1],
        intermediates[1:],
    ):
        attack.add_edge(
            source,
            destination,
            step_type="candidate_compromise",
        )

    return attack


def run_once(host_count, vulns_per_host):
    tracemalloc.start()

    start = time.perf_counter()

    graph, attacker, target, intermediates = (
        build_graph(
            host_count,
            vulns_per_host,
        )
    )

    attack = build_attack_graph(
        attacker,
        target,
        intermediates,
    )

    paths = list(
        nx.all_simple_paths(
            attack,
            attacker,
            target,
        )
    )

    elapsed = time.perf_counter() - start

    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    vulnerability_nodes = sum(
        1
        for _, data in graph.nodes(data=True)
        if data.get("type") == "vulnerability"
    )

    return {
        "graph_nodes": graph.number_of_nodes(),
        "graph_edges": graph.number_of_edges(),
        "attack_nodes": attack.number_of_nodes(),
        "attack_edges": attack.number_of_edges(),
        "vulnerability_count": vulnerability_nodes,
        "path_count": len(paths),
        "execution_seconds": elapsed,
        "peak_memory_mb": peak / (1024 * 1024),
    }


rows = []

for scenario, hosts, vulns in SCENARIOS:
    print(
        f"\n{scenario}: "
        f"{hosts} hosts, "
        f"{vulns} vulnerabilities per "
        f"intermediate host"
    )

    for run in range(1, REPEATS + 1):
        result = run_once(
            hosts,
            vulns,
        )

        result.update({
            "scenario": scenario,
            "run": run,
            "host_count": hosts,
            "vulns_per_host": vulns,
        })

        rows.append(result)

        print(
            f"Run {run}: "
            f"{result['graph_nodes']} nodes, "
            f"{result['vulnerability_count']} vulns, "
            f"{result['path_count']} paths, "
            f"{result['execution_seconds']:.4f} s"
        )


runs = pd.DataFrame(rows)

runs.to_csv(
    OUT / "scalability_runs.csv",
    index=False,
)


summary = (
    runs.groupby(
        [
            "scenario",
            "host_count",
            "vulns_per_host",
        ]
    )
    .agg(
        vulnerability_count=(
            "vulnerability_count",
            "first",
        ),
        graph_nodes=(
            "graph_nodes",
            "first",
        ),
        graph_edges=(
            "graph_edges",
            "first",
        ),
        attack_nodes=(
            "attack_nodes",
            "first",
        ),
        attack_edges=(
            "attack_edges",
            "first",
        ),
        path_count=(
            "path_count",
            "first",
        ),
        mean_seconds=(
            "execution_seconds",
            "mean",
        ),
        median_seconds=(
            "execution_seconds",
            "median",
        ),
        min_seconds=(
            "execution_seconds",
            "min",
        ),
        max_seconds=(
            "execution_seconds",
            "max",
        ),
        mean_peak_memory_mb=(
            "peak_memory_mb",
            "mean",
        ),
    )
    .reset_index()
)

summary.to_csv(
    OUT / "scalability_summary.csv",
    index=False,
)

print("\nScalability summary:")
print(summary.to_string(index=False))