from __future__ import annotations

from typing import Any

import networkx as nx

from risk_prioritization.risk_scorer import (
    score_attack_path,
)


def prioritize_attack_paths(
    graph: nx.MultiDiGraph,
    paths: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Score and rank attack paths from highest to lowest risk."""

    ranked_paths: list[dict[str, Any]] = []

    for path in paths:
        scoring = score_attack_path(graph, path)

        ranked_path = dict(path)
        ranked_path.update(scoring)

        ranked_paths.append(ranked_path)

    ranked_paths.sort(
        key=lambda path: (
            -float(path["risk_score"]),
            -float(path["maximum_epss"]),
            -float(path["maximum_cvss"]),
            int(path["hop_count"]),
            path["path_id"],
        )
    )

    for rank, path in enumerate(ranked_paths, start=1):
        path["rank"] = rank

    return ranked_paths