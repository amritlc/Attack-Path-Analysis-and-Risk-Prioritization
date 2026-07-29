from __future__ import annotations

from statistics import mean
from typing import Any

import networkx as nx


CONFIDENCE_VALUES = {
    "high": 1.0,
    "medium": 0.75,
    "low": 0.50,
}


def safe_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(value, maximum))


def risk_level(score: float) -> str:
    if score >= 75:
        return "Critical"

    if score >= 55:
        return "High"

    if score >= 30:
        return "Medium"

    return "Low"


def score_attack_path(
    graph: nx.MultiDiGraph,
    path: dict[str, Any],
) -> dict[str, Any]:
    """
    Calculate an interpretable risk score for one attack path.

    Components:
    - CVSS severity: 40%
    - EPSS exploitation probability: 30%
    - CISA KEV status: 10%
    - Final asset criticality: 15%
    - Path efficiency: 5%

    Access-condition confidence and scenario assumptions are
    applied as evidence-quality multipliers.
    """

    vulnerability_nodes: list[dict[str, Any]] = []
    access_condition_nodes: list[dict[str, Any]] = []

    for node_id in path["node_ids"]:
        attributes = graph.nodes[node_id]
        node_type = attributes.get("node_type")

        if node_type == "vulnerability":
            vulnerability_nodes.append(attributes)

        elif node_type == "access_condition":
            access_condition_nodes.append(attributes)

    if not vulnerability_nodes:
        raise ValueError(
            f"{path['path_id']} contains no vulnerability nodes."
        )

    cvss_values: list[float] = []
    epss_values: list[float] = []
    kev_flags: list[float] = []

    cve_count = 0

    for vulnerability in vulnerability_nodes:
        openvas_cvss = safe_float(
            vulnerability.get("openvas_cvss")
        )

        nvd_cvss = safe_float(
            vulnerability.get("nvd_cvss")
        )

        selected_cvss = max(openvas_cvss, nvd_cvss)

        cvss_values.append(
            clamp(selected_cvss / 10.0, 0.0, 1.0)
        )

        epss_values.append(
            clamp(
                safe_float(vulnerability.get("epss")),
                0.0,
                1.0,
            )
        )

        kev_flags.append(
            1.0 if vulnerability.get("kev") is True else 0.0
        )

        if vulnerability.get("cve_id"):
            cve_count += 1

    cvss_component = mean(cvss_values)
    epss_component = mean(epss_values)
    kev_component = max(kev_flags)

    final_node_id = path["node_ids"][-1]
    final_asset = graph.nodes[final_node_id]

    criticality_score = safe_float(
        final_asset.get("criticality_score")
    )

    asset_criticality_component = clamp(
        criticality_score / 5.0,
        0.0,
        1.0,
    )

    stage_count = (
        len(vulnerability_nodes)
        + len(access_condition_nodes)
    )

    path_efficiency_component = 1.0 / (
        1.0 + 0.12 * max(stage_count - 1, 0)
    )

    raw_score = 100.0 * (
        0.40 * cvss_component
        + 0.30 * epss_component
        + 0.10 * kev_component
        + 0.15 * asset_criticality_component
        + 0.05 * path_efficiency_component
    )

    confidence_values: list[float] = []
    scenario_assumption_count = 0

    for condition in access_condition_nodes:
        confidence = str(
            condition.get("confidence", "")
        ).lower()

        confidence_values.append(
            CONFIDENCE_VALUES.get(confidence, 0.50)
        )

        if (
            condition.get("evidence_type")
            == "scenario_assumption"
        ):
            scenario_assumption_count += 1

    average_access_confidence = (
        mean(confidence_values)
        if confidence_values
        else 1.0
    )

    # Prevent assumptions from completely dominating the score.
    evidence_multiplier = (
        0.75 + 0.25 * average_access_confidence
    )

    assumption_multiplier = max(
        0.70,
        1.0 - 0.05 * scenario_assumption_count,
    )

    final_score = clamp(
        raw_score
        * evidence_multiplier
        * assumption_multiplier,
        0.0,
        100.0,
    )

    cve_coverage = (
        cve_count / len(vulnerability_nodes)
        if vulnerability_nodes
        else 0.0
    )

    return {
        "path_id": path["path_id"],
        "risk_score": round(final_score, 4),
        "risk_level": risk_level(final_score),
        "raw_score": round(raw_score, 4),
        "cvss_component": round(cvss_component, 6),
        "epss_component": round(epss_component, 6),
        "kev_component": round(kev_component, 6),
        "asset_criticality_component": round(
            asset_criticality_component,
            6,
        ),
        "path_efficiency_component": round(
            path_efficiency_component,
            6,
        ),
        "average_access_confidence": round(
            average_access_confidence,
            6,
        ),
        "evidence_multiplier": round(
            evidence_multiplier,
            6,
        ),
        "assumption_multiplier": round(
            assumption_multiplier,
            6,
        ),
        "scenario_assumption_count": (
            scenario_assumption_count
        ),
        "cve_coverage": round(cve_coverage, 6),
    }