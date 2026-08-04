from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

VULNERABILITY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "enriched_vulnerability_findings.csv"
)

ASSET_FILE = (
    PROJECT_ROOT
    / "data"
    / "manual"
    / "assets.csv"
)

RESULTS_DIR = (
    PROJECT_ROOT
    / "experiments"
    / "experiment2"
    / "results"
)

RANKING_FILE = RESULTS_DIR / "host_based_ranking.csv"
SUMMARY_FILE = RESULTS_DIR / "host_based_summary.csv"


def safe_numeric(
    series: pd.Series,
) -> pd.Series:
    """Convert a pandas Series to numeric values safely."""

    return pd.to_numeric(
        series,
        errors="coerce",
    ).fillna(0.0)


def risk_level(score: float) -> str:
    """Convert a numerical score into a risk category."""

    if score >= 75:
        return "Critical"

    if score >= 55:
        return "High"

    if score >= 30:
        return "Medium"

    return "Low"


def normalise_boolean(
    series: pd.Series,
) -> pd.Series:
    """Convert common boolean representations to zero or one."""

    true_values = {
        "1",
        "true",
        "yes",
        "y",
    }

    return (
        series.astype(str)
        .str.strip()
        .str.lower()
        .isin(true_values)
        .astype(int)
    )


def create_vulnerability_identifier(
    dataframe: pd.DataFrame,
) -> pd.Series:
    """Select the strongest available identifier for each finding."""

    cve = dataframe.get(
        "cve_id",
        pd.Series("", index=dataframe.index),
    ).fillna("").astype(str).str.strip()

    nvt_oid = dataframe.get(
        "nvt_oid",
        pd.Series("", index=dataframe.index),
    ).fillna("").astype(str).str.strip()

    nvt_name = dataframe.get(
        "nvt_name",
        pd.Series("", index=dataframe.index),
    ).fillna("").astype(str).str.strip()

    identifier = cve.copy()

    identifier = identifier.mask(
        identifier == "",
        nvt_oid,
    )

    identifier = identifier.mask(
        identifier == "",
        nvt_name,
    )

    identifier = identifier.mask(
        identifier == "",
        "unknown-finding",
    )

    return identifier


def prepare_unique_vulnerabilities(
    vulnerabilities: pd.DataFrame,
) -> pd.DataFrame:
    """
    Create one row for each unique host-service-vulnerability
    relationship.
    """

    vulnerabilities = vulnerabilities.copy()

    vulnerabilities["ip_address"] = (
        vulnerabilities["ip_address"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    vulnerabilities["protocol"] = (
        vulnerabilities.get(
            "protocol",
            pd.Series("", index=vulnerabilities.index),
        )
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
    )

    vulnerabilities["port"] = safe_numeric(
        vulnerabilities.get(
            "port",
            pd.Series(0, index=vulnerabilities.index),
        )
    ).astype(int)

    vulnerabilities["vulnerability_identifier"] = (
        create_vulnerability_identifier(
            vulnerabilities
        )
    )

    openvas_cvss = safe_numeric(
        vulnerabilities.get(
            "cvss",
            pd.Series(0, index=vulnerabilities.index),
        )
    )

    nvd_cvss = safe_numeric(
        vulnerabilities.get(
            "nvd_base_score",
            pd.Series(0, index=vulnerabilities.index),
        )
    )

    vulnerabilities["selected_cvss"] = np.maximum(
        openvas_cvss,
        nvd_cvss,
    )

    vulnerabilities["epss_value"] = safe_numeric(
        vulnerabilities.get(
            "epss",
            pd.Series(0, index=vulnerabilities.index),
        )
    ).clip(
        lower=0.0,
        upper=1.0,
    )

    vulnerabilities["kev_value"] = normalise_boolean(
        vulnerabilities.get(
            "kev",
            pd.Series("", index=vulnerabilities.index),
        )
    )

    vulnerabilities["has_cve"] = (
        vulnerabilities.get(
            "cve_id",
            pd.Series("", index=vulnerabilities.index),
        )
        .fillna("")
        .astype(str)
        .str.strip()
        .ne("")
        .astype(int)
    )

    unique_columns = [
        "ip_address",
        "protocol",
        "port",
        "vulnerability_identifier",
    ]

    unique_vulnerabilities = (
        vulnerabilities.sort_values(
            by=[
                "selected_cvss",
                "epss_value",
                "kev_value",
            ],
            ascending=False,
        )
        .drop_duplicates(
            subset=unique_columns,
            keep="first",
        )
    )

    return unique_vulnerabilities


def aggregate_host_risk(
    vulnerabilities: pd.DataFrame,
) -> pd.DataFrame:
    """Aggregate vulnerability evidence independently by host."""

    return (
        vulnerabilities.groupby(
            "ip_address",
            as_index=False,
        )
        .agg(
            unique_vulnerability_count=(
                "vulnerability_identifier",
                "nunique",
            ),
            cve_count=(
                "has_cve",
                "sum",
            ),
            maximum_cvss=(
                "selected_cvss",
                "max",
            ),
            mean_cvss=(
                "selected_cvss",
                "mean",
            ),
            maximum_epss=(
                "epss_value",
                "max",
            ),
            mean_epss=(
                "epss_value",
                "mean",
            ),
            kev_count=(
                "kev_value",
                "sum",
            ),
            exposed_port_count=(
                "port",
                lambda values: (
                    values[values > 0].nunique()
                ),
            ),
        )
    )


def create_host_based_ranking() -> None:
    """
    Rank hosts without using graph paths, lateral movement,
    access conditions or target reachability.
    """

    if not VULNERABILITY_FILE.exists():
        raise FileNotFoundError(
            f"Vulnerability file not found: "
            f"{VULNERABILITY_FILE}"
        )

    if not ASSET_FILE.exists():
        raise FileNotFoundError(
            f"Asset file not found: {ASSET_FILE}"
        )

    vulnerabilities = pd.read_csv(
        VULNERABILITY_FILE
    )

    assets = pd.read_csv(
        ASSET_FILE
    )

    required_asset_columns = {
        "asset_id",
        "ip_address",
        "hostname",
        "asset_type",
        "zone",
        "criticality",
        "criticality_score",
        "is_primary_target",
    }

    missing_asset_columns = (
        required_asset_columns
        - set(assets.columns)
    )

    if missing_asset_columns:
        raise ValueError(
            "Asset dataset is missing columns: "
            f"{sorted(missing_asset_columns)}"
        )

    unique_vulnerabilities = (
        prepare_unique_vulnerabilities(
            vulnerabilities
        )
    )

    host_statistics = aggregate_host_risk(
        unique_vulnerabilities
    )

    ranking = assets.merge(
        host_statistics,
        on="ip_address",
        how="left",
    )

    numeric_columns = [
        "unique_vulnerability_count",
        "cve_count",
        "maximum_cvss",
        "mean_cvss",
        "maximum_epss",
        "mean_epss",
        "kev_count",
        "exposed_port_count",
        "criticality_score",
    ]

    for column in numeric_columns:
        ranking[column] = safe_numeric(
            ranking[column]
        )

    ranking["nvt_only_count"] = (
        ranking["unique_vulnerability_count"]
        - ranking["cve_count"]
    ).clip(lower=0)

    ranking["kev_present"] = (
        ranking["kev_count"] > 0
    ).astype(int)

    ranking["cvss_component"] = (
        ranking["maximum_cvss"] / 10.0
    ).clip(
        lower=0.0,
        upper=1.0,
    )

    ranking["epss_component"] = (
        ranking["maximum_epss"]
    ).clip(
        lower=0.0,
        upper=1.0,
    )

    ranking["kev_component"] = (
        ranking["kev_present"]
    )

    ranking["asset_criticality_component"] = (
        ranking["criticality_score"] / 5.0
    ).clip(
        lower=0.0,
        upper=1.0,
    )

    maximum_burden = np.log1p(
        ranking["unique_vulnerability_count"]
    ).max()

    if maximum_burden > 0:
        ranking["vulnerability_burden_component"] = (
            np.log1p(
                ranking["unique_vulnerability_count"]
            )
            / maximum_burden
        )
    else:
        ranking["vulnerability_burden_component"] = 0.0

    # Traditional host-based score:
    # no graph structure or attack-path context is used.
    ranking["host_risk_score"] = 100.0 * (
        0.40 * ranking["cvss_component"]
        + 0.25 * ranking["epss_component"]
        + 0.10 * ranking["kev_component"]
        + 0.15
        * ranking["asset_criticality_component"]
        + 0.10
        * ranking["vulnerability_burden_component"]
    )

    ranking["host_risk_score"] = (
        ranking["host_risk_score"]
        .clip(
            lower=0.0,
            upper=100.0,
        )
        .round(4)
    )

    ranking["host_risk_level"] = ranking[
        "host_risk_score"
    ].apply(risk_level)

    ranking = ranking.sort_values(
        by=[
            "host_risk_score",
            "maximum_epss",
            "maximum_cvss",
            "criticality_score",
        ],
        ascending=False,
    ).reset_index(drop=True)

    ranking["host_rank"] = (
        ranking.index + 1
    )

    ranking["is_primary_target"] = (
        ranking["is_primary_target"]
        .fillna("")
        .astype(str)
    )

    output_columns = [
        "host_rank",
        "asset_id",
        "ip_address",
        "hostname",
        "asset_type",
        "zone",
        "criticality",
        "criticality_score",
        "is_primary_target",
        "host_risk_score",
        "host_risk_level",
        "unique_vulnerability_count",
        "cve_count",
        "nvt_only_count",
        "maximum_cvss",
        "mean_cvss",
        "maximum_epss",
        "mean_epss",
        "kev_count",
        "kev_present",
        "exposed_port_count",
        "cvss_component",
        "epss_component",
        "kev_component",
        "asset_criticality_component",
        "vulnerability_burden_component",
    ]

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    ranking[output_columns].to_csv(
        RANKING_FILE,
        index=False,
    )

    primary_target = ranking[
        ranking["is_primary_target"]
        .str.lower()
        .eq("yes")
    ]

    summary_rows = [
        {
            "metric": "hosts_ranked",
            "value": len(ranking),
        },
        {
            "metric": "unique_vulnerabilities",
            "value": len(unique_vulnerabilities),
        },
        {
            "metric": "hosts_with_kev",
            "value": int(
                ranking["kev_present"].sum()
            ),
        },
        {
            "metric": "primary_target_host_rank",
            "value": (
                int(primary_target["host_rank"].iloc[0])
                if not primary_target.empty
                else ""
            ),
        },
        {
            "metric": "primary_target_host_score",
            "value": (
                float(
                    primary_target[
                        "host_risk_score"
                    ].iloc[0]
                )
                if not primary_target.empty
                else ""
            ),
        },
    ]

    pd.DataFrame(summary_rows).to_csv(
        SUMMARY_FILE,
        index=False,
    )

    print("Traditional host-based ranking completed.")
    print()

    print(
        ranking[
            [
                "host_rank",
                "hostname",
                "ip_address",
                "host_risk_score",
                "host_risk_level",
                "unique_vulnerability_count",
                "maximum_cvss",
                "maximum_epss",
                "kev_present",
                "is_primary_target",
            ]
        ].to_string(index=False)
    )

    print()
    print(f"Host ranking: {RANKING_FILE}")
    print(f"Summary: {SUMMARY_FILE}")


if __name__ == "__main__":
    create_host_based_ranking()