from attack_graph.path_finder import find_attack_paths
from graph_builder.build_graph import build_attack_graph
from risk_prioritization.path_prioritizer import (
    prioritize_attack_paths,
)


def main() -> None:
    graph = build_attack_graph()
    paths = find_attack_paths(graph)
    ranked_paths = prioritize_attack_paths(graph, paths)

    print(f"Complete attack paths: {len(paths)}")
    print()

    print("Top 10 prioritised attack paths:")

    for path in ranked_paths[:10]:
        print()
        print(
            f"Rank {path['rank']} | "
            f"{path['path_id']} | "
            f"Risk: {path['risk_score']:.2f}/100 | "
            f"Level: {path['risk_level']}"
        )

        print(" -> ".join(path["labels"]))

        print(
            f"CVSS component: "
            f"{path['cvss_component']:.3f} | "
            f"EPSS component: "
            f"{path['epss_component']:.3f} | "
            f"KEV: {path['kev_component']:.0f}"
        )

        print(
            f"CVE coverage: "
            f"{path['cve_coverage']:.2f} | "
            f"Scenario assumptions: "
            f"{path['scenario_assumption_count']}"
        )


if __name__ == "__main__":
    main()