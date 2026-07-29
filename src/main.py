from graph_builder.build_graph import (
    build_attack_graph,
    get_graph_summary,
)


def main() -> None:
    graph = build_attack_graph()
    summary = get_graph_summary(graph)

    print("Attack graph created successfully.")
    print()

    for metric, value in summary.items():
        print(f"{metric}: {value}")


if __name__ == "__main__":
    main()