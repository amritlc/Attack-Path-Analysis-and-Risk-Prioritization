from __future__ import annotations

from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

HOST_RANKING_FILE = (
    PROJECT_ROOT
    / "experiments"
    / "experiment2"
    / "results"
    / "host_based_ranking.csv"
)

RANKED_PATHS_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "ranked_attack_paths.csv"
)

HYBRID_PATHS_FILE = (
    PROJECT_ROOT
    / "experiments"
    / "experiment1"
    / "results"
    / "hybrid_ai_ranked_paths.csv"
)

RESULTS_DIR = (
    PROJECT_ROOT
    / "experiments"
    / "experiment2"
    / "results"
)

COMPARISON_FILE = (
    RESULTS_DIR
    / "host_vs_graph_comparison.csv"
)

TOP_PATHS_FILE = (
    RESULTS_DIR
    / "top_graph_paths_to_primary_target.csv"
)


def normalise_yes_no(series: pd.Series) -> pd.Series:
    """Return True for common positive representations."""

    return (
        series.fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
        .isin({"yes", "true", "1", "y"})
    )


def compare_methods() -> None:
    """Compare host-based and graph-based prioritisation."""

    for required_file in [
        HOST_RANKING_FILE,
        RANKED_PATHS_FILE,
        HYBRID_PATHS_FILE,
    ]:
        if not required_file.exists():
            raise FileNotFoundError(
                f"Required file not found: {required_file}"
            )

    hosts = pd.read_csv(HOST_RANKING_FILE)
    ranked_paths = pd.read_csv(RANKED_PATHS_FILE)
    hybrid_paths = pd.read_csv(HYBRID_PATHS_FILE)

    required_host_columns = {
        "host_rank",
        "hostname",
        "host_risk_score",
        "host_risk_level",
        "is_primary_target",
    }

    required_path_columns = {
        "path_id",
        "final_target",
        "path_labels",
        "vulnerabilities",
        "access_conditions",
    }

    required_hybrid_columns = {
        "path_id",
        "hybrid_rank",
        "hybrid_ai_score",
        "hybrid_risk_level",
        "score_source",
    }

    missing_host = (
        required_host_columns - set(hosts.columns)
    )

    missing_paths = (
        required_path_columns - set(ranked_paths.columns)
    )

    missing_hybrid = (
        required_hybrid_columns - set(hybrid_paths.columns)
    )

    if missing_host:
        raise ValueError(
            f"Host ranking is missing: {sorted(missing_host)}"
        )

    if missing_paths:
        raise ValueError(
            f"Ranked paths are missing: {sorted(missing_paths)}"
        )

    if missing_hybrid:
        raise ValueError(
            f"Hybrid paths are missing: {sorted(missing_hybrid)}"
        )

    primary_target_mask = normalise_yes_no(
        hosts["is_primary_target"]
    )

    primary_targets = hosts[primary_target_mask]

    if primary_targets.empty:
        raise ValueError(
            "No primary target was found in the host ranking."
        )

    primary_target = primary_targets.iloc[0]

    target_hostname = str(
        primary_target["hostname"]
    ).strip()

    merged_paths = ranked_paths.merge(
        hybrid_paths[
            [
                "path_id",
                "hybrid_rank",
                "hybrid_ai_score",
                "hybrid_risk_level",
                "score_source",
            ]
        ],
        on="path_id",
        how="inner",
    )

    target_paths = merged_paths[
        merged_paths["final_target"]
        .astype(str)
        .str.strip()
        .eq(target_hostname)
    ].copy()

    if target_paths.empty:
        raise ValueError(
            f"No graph paths were found for {target_hostname}."
        )

    target_paths = target_paths.sort_values(
        by=[
            "hybrid_rank",
            "hybrid_ai_score",
        ],
        ascending=[
            True,
            False,
        ],
    )

    highest_path = target_paths.iloc[0]

    critical_paths = int(
        target_paths["hybrid_risk_level"]
        .astype(str)
        .eq("Critical")
        .sum()
    )

    high_paths = int(
        target_paths["hybrid_risk_level"]
        .astype(str)
        .eq("High")
        .sum()
    )

    medium_paths = int(
        target_paths["hybrid_risk_level"]
        .astype(str)
        .eq("Medium")
        .sum()
    )

    low_paths = int(
        target_paths["hybrid_risk_level"]
        .astype(str)
        .eq("Low")
        .sum()
    )

    host_score = float(
        primary_target["host_risk_score"]
    )

    graph_score = float(
        highest_path["hybrid_ai_score"]
    )

    comparison_rows = [
        {
            "metric": "Primary target",
            "host_based_result": target_hostname,
            "graph_based_result": target_hostname,
            "interpretation": (
                "Both approaches evaluate the same critical asset."
            ),
        },
        {
            "metric": "Primary target rank",
            "host_based_result": int(
                primary_target["host_rank"]
            ),
            "graph_based_result": (
                "Reached by ranked attack paths"
            ),
            "interpretation": (
                "The host approach ranks the database using "
                "only its local vulnerabilities."
            ),
        },
        {
            "metric": "Primary target local risk",
            "host_based_result": (
                f"{host_score:.4f} "
                f"({primary_target['host_risk_level']})"
            ),
            "graph_based_result": "Not applicable",
            "interpretation": (
                "The database has little directly observed "
                "vulnerability evidence."
            ),
        },
        {
            "metric": "Complete paths to primary target",
            "host_based_result": 0,
            "graph_based_result": len(target_paths),
            "interpretation": (
                "Host-based ranking does not represent "
                "multi-stage reachability."
            ),
        },
        {
            "metric": "Highest contextual path risk",
            "host_based_result": "Not available",
            "graph_based_result": (
                f"{graph_score:.4f} "
                f"({highest_path['hybrid_risk_level']})"
            ),
            "interpretation": (
                "The graph model identifies the risk created "
                "by entry-host compromise and lateral movement."
            ),
        },
        {
            "metric": "Critical target paths",
            "host_based_result": "Not available",
            "graph_based_result": critical_paths,
            "interpretation": (
                "Critical paths require topology and "
                "attack-stage context."
            ),
        },
        {
            "metric": "High target paths",
            "host_based_result": "Not available",
            "graph_based_result": high_paths,
            "interpretation": (
                "High-risk routes are prioritised separately."
            ),
        },
        {
            "metric": "Medium target paths",
            "host_based_result": "Not available",
            "graph_based_result": medium_paths,
            "interpretation": (
                "The graph model retains lower-priority routes."
            ),
        },
        {
            "metric": "Low target paths",
            "host_based_result": "Not available",
            "graph_based_result": low_paths,
            "interpretation": (
                "Low-risk paths remain visible for review."
            ),
        },
        {
            "metric": "Highest-risk path",
            "host_based_result": "Not represented",
            "graph_based_result": highest_path[
                "path_labels"
            ],
            "interpretation": (
                "Only the graph model explains the complete "
                "route from attacker to target."
            ),
        },
    ]

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    comparison = pd.DataFrame(comparison_rows)

    comparison.to_csv(
        COMPARISON_FILE,
        index=False,
    )

    top_columns = [
        "hybrid_rank",
        "path_id",
        "hybrid_ai_score",
        "hybrid_risk_level",
        "vulnerabilities",
        "access_conditions",
        "path_labels",
        "score_source",
    ]

    target_paths[top_columns].head(10).to_csv(
        TOP_PATHS_FILE,
        index=False,
    )

    print("Host-based versus graph-based comparison completed.")
    print()

    print(
        comparison[
            [
                "metric",
                "host_based_result",
                "graph_based_result",
            ]
        ].to_string(index=False)
    )

    print()
    print(f"Comparison: {COMPARISON_FILE}")
    print(f"Top target paths: {TOP_PATHS_FILE}")


if __name__ == "__main__":
    compare_methods()