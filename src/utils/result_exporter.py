from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = PROJECT_ROOT / "data" / "processed"

RANKED_PATHS_FILE = OUTPUT_DIR / "ranked_attack_paths.csv"
RANKED_PATHS_JSON = OUTPUT_DIR / "ranked_attack_paths.json"
SUMMARY_FILE = OUTPUT_DIR / "risk_ranking_summary.csv"


def serialise_list(value: Any) -> str:
    """Convert list values into readable semicolon-separated text."""

    if isinstance(value, list):
        return ";".join(str(item) for item in value)

    return str(value or "")


def export_ranked_paths(
    ranked_paths: list[dict[str, Any]],
) -> None:
    """Export ranked attack paths and risk summary files."""

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    csv_rows: list[dict[str, Any]] = []

    for path in ranked_paths:
        csv_rows.append(
            {
                "rank": path["rank"],
                "path_id": path["path_id"],
                "risk_score": path["risk_score"],
                "risk_level": path["risk_level"],
                "hop_count": path["hop_count"],
                "exploit_stage_count": path[
                    "exploit_stage_count"
                ],
                "access_condition_count": path[
                    "access_condition_count"
                ],
                "final_target": path["final_target"],
                "maximum_cvss": path["maximum_cvss"],
                "maximum_epss": path["maximum_epss"],
                "kev_present": path["kev_present"],
                "cvss_component": path["cvss_component"],
                "epss_component": path["epss_component"],
                "kev_component": path["kev_component"],
                "asset_criticality_component": path[
                    "asset_criticality_component"
                ],
                "path_efficiency_component": path[
                    "path_efficiency_component"
                ],
                "average_access_confidence": path[
                    "average_access_confidence"
                ],
                "evidence_multiplier": path[
                    "evidence_multiplier"
                ],
                "assumption_multiplier": path[
                    "assumption_multiplier"
                ],
                "scenario_assumption_count": path[
                    "scenario_assumption_count"
                ],
                "cve_coverage": path["cve_coverage"],
                "vulnerabilities": serialise_list(
                    path["vulnerabilities"]
                ),
                "access_conditions": serialise_list(
                    path["access_conditions"]
                ),
                "compromised_assets": serialise_list(
                    path["compromised_assets"]
                ),
                "path_labels": " -> ".join(path["labels"]),
                "node_ids": serialise_list(path["node_ids"]),
            }
        )

    fieldnames = list(csv_rows[0].keys())

    with RANKED_PATHS_FILE.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)

    with RANKED_PATHS_JSON.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            ranked_paths,
            file,
            indent=2,
            ensure_ascii=False,
            default=str,
        )

    risk_counts = Counter(
        path["risk_level"] for path in ranked_paths
    )

    summary_rows = [
        {
            "metric": "total_ranked_paths",
            "value": len(ranked_paths),
        },
        {
            "metric": "critical_paths",
            "value": risk_counts["Critical"],
        },
        {
            "metric": "high_paths",
            "value": risk_counts["High"],
        },
        {
            "metric": "medium_paths",
            "value": risk_counts["Medium"],
        },
        {
            "metric": "low_paths",
            "value": risk_counts["Low"],
        },
        {
            "metric": "paths_with_kev",
            "value": sum(
                bool(path["kev_present"])
                for path in ranked_paths
            ),
        },
        {
            "metric": "paths_with_complete_cve_coverage",
            "value": sum(
                float(path["cve_coverage"]) == 1.0
                for path in ranked_paths
            ),
        },
    ]

    with SUMMARY_FILE.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["metric", "value"],
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    print(f"Ranked paths exported: {RANKED_PATHS_FILE}")
    print(f"JSON paths exported: {RANKED_PATHS_JSON}")
    print(f"Risk summary exported: {SUMMARY_FILE}")