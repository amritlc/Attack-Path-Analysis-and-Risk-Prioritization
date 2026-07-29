from __future__ import annotations

import csv
from pathlib import Path
from statistics import mean
from typing import Any

import networkx as nx

PROJECT_ROOT = Path(__file__).resolve().parents[2]

OUTPUT_FILE = PROJECT_ROOT / "data" / "processed" / "ml_path_features.csv"

CONFIDENCE_VALUES = {
    "high": 1.0,
    "medium": 0.75,
    "low": 0.50,
}


def safe_float(value: Any) -> float:
    """Convert a value to float safely."""

    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def selected_cvss(
    vulnerability: dict[str, Any],
) -> float:
    """Use the highest available OpenVAS or NVD CVSS."""

    return max(
        safe_float(vulnerability.get("openvas_cvss")),
        safe_float(vulnerability.get("nvd_cvss")),
    )


def build_path_feature_rows(
    graph: nx.MultiDiGraph,
    ranked_paths: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert attack paths into machine-learning features."""

    rows: list[dict[str, Any]] = []

    for path in ranked_paths:
        vulnerabilities: list[dict[str, Any]] = []
        access_conditions: list[dict[str, Any]] = []
        services: list[dict[str, Any]] = []
        assets: list[dict[str, Any]] = []

        for node_id in path["node_ids"]:
            attributes = graph.nodes[node_id]
            node_type = attributes.get("node_type")

            if node_type == "vulnerability":
                vulnerabilities.append(attributes)

            elif node_type == "access_condition":
                access_conditions.append(attributes)

            elif node_type == "service":
                services.append(attributes)

            elif node_type == "asset":
                assets.append(attributes)
                vulnerability_identifiers: list[str] = []

        for vulnerability in vulnerabilities:
            identifier = (
                vulnerability.get("cve_id")
                or vulnerability.get("nvt_oid")
                or vulnerability.get("label")
                or "unknown"
            )

            vulnerability_identifiers.append(str(identifier))

        vulnerability_signature = ";".join(sorted(set(vulnerability_identifiers)))

        cvss_values = [
            selected_cvss(vulnerability) for vulnerability in vulnerabilities
        ]

        epss_values = [
            safe_float(vulnerability.get("epss")) for vulnerability in vulnerabilities
        ]

        cve_count = sum(
            bool(vulnerability.get("cve_id")) for vulnerability in vulnerabilities
        )

        nvt_only_count = len(vulnerabilities) - cve_count

        kev_count = sum(
            vulnerability.get("kev") is True for vulnerability in vulnerabilities
        )

        confidence_values = [
            CONFIDENCE_VALUES.get(
                str(condition.get("confidence", "")).lower(),
                0.50,
            )
            for condition in access_conditions
        ]

        scenario_assumption_count = sum(
            condition.get("evidence_type") == "scenario_assumption"
            for condition in access_conditions
        )

        observed_condition_count = len(access_conditions) - scenario_assumption_count

        entry_service = services[0] if services else {}
        entry_asset = assets[0] if assets else {}

        final_asset_id = path["node_ids"][-1]
        final_asset = graph.nodes[final_asset_id]

        vulnerability_count = len(vulnerabilities)

        rows.append(
            {
                "path_id": path["path_id"],
                "vulnerability_signature": vulnerability_signature,
                "baseline_rank": path["rank"],
                "entry_service_name": entry_service.get(
                    "service_name",
                    "unknown",
                ),
                "entry_service_port": entry_service.get(
                    "port",
                    0,
                ),
                "entry_protocol": entry_service.get(
                    "protocol",
                    "unknown",
                ),
                "entry_asset_type": entry_asset.get(
                    "asset_type",
                    "unknown",
                ),
                "entry_zone": entry_asset.get(
                    "zone",
                    "unknown",
                ),
                "entry_asset_criticality": safe_float(
                    entry_asset.get("criticality_score")
                ),
                "target_asset_type": final_asset.get(
                    "asset_type",
                    "unknown",
                ),
                "target_zone": final_asset.get(
                    "zone",
                    "unknown",
                ),
                "target_criticality_score": safe_float(
                    final_asset.get("criticality_score")
                ),
                "vulnerability_count": vulnerability_count,
                "cve_count": cve_count,
                "nvt_only_count": nvt_only_count,
                "cve_coverage": (
                    cve_count / vulnerability_count if vulnerability_count else 0.0
                ),
                "maximum_cvss": (max(cvss_values) if cvss_values else 0.0),
                "mean_cvss": (mean(cvss_values) if cvss_values else 0.0),
                "minimum_cvss": (min(cvss_values) if cvss_values else 0.0),
                "maximum_epss": (max(epss_values) if epss_values else 0.0),
                "mean_epss": (mean(epss_values) if epss_values else 0.0),
                "kev_count": kev_count,
                "kev_present": int(kev_count > 0),
                "hop_count": path["hop_count"],
                "exploit_stage_count": path["exploit_stage_count"],
                "access_condition_count": path["access_condition_count"],
                "scenario_assumption_count": (scenario_assumption_count),
                "observed_condition_count": (observed_condition_count),
                "average_access_confidence": (
                    mean(confidence_values) if confidence_values else 1.0
                ),
                "baseline_risk_score": path["risk_score"],
                "baseline_risk_level": path["risk_level"],
            }
        )

    return rows


def export_path_feature_dataset(
    graph: nx.MultiDiGraph,
    ranked_paths: list[dict[str, Any]],
) -> Path:
    """Export the ML-ready attack-path feature dataset."""

    rows = build_path_feature_rows(
        graph,
        ranked_paths,
    )

    if not rows:
        raise ValueError("No attack-path features were generated.")

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
        mode="w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=list(rows[0].keys()),
        )

        writer.writeheader()
        writer.writerows(rows)

    print(f"ML feature rows exported: {len(rows)}")
    print(f"ML feature dataset: {OUTPUT_FILE}")

    return OUTPUT_FILE
