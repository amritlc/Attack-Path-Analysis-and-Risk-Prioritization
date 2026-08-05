from __future__ import annotations

from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    mean_absolute_error,
    mean_squared_error,
    r2_score,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    PROJECT_ROOT
    / "experiments"
    / "experiment1"
    / "results"
    / "grouped_model_comparison_predictions.csv"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "experiments"
    / "experiment1"
    / "results"
    / "hybrid_ai_ranked_paths.csv"
)

METRICS_FILE = (
    PROJECT_ROOT
    / "experiments"
    / "experiment1"
    / "results"
    / "hybrid_ai_metrics.csv"
)


def risk_level(score: float) -> str:
    """Convert a numeric risk score into a risk category."""

    if score >= 75:
        return "Critical"

    if score >= 55:
        return "High"

    if score >= 30:
        return "Medium"

    return "Low"


def rank_correlation(
    actual: pd.Series,
    predicted: pd.Series,
) -> float:
    """Calculate correlation between actual and predicted ranks."""

    actual_rank = actual.rank(
        method="average",
        ascending=False,
    )

    predicted_rank = predicted.rank(
        method="average",
        ascending=False,
    )

    correlation = actual_rank.corr(predicted_rank)

    if pd.isna(correlation):
        return 0.0

    return float(correlation)


def top_k_overlap(
    actual: pd.Series,
    predicted: pd.Series,
    k: int = 10,
) -> float:
    """Calculate overlap between actual and predicted top-k paths."""

    effective_k = min(k, len(actual))

    actual_top = set(
        actual.nlargest(effective_k).index
    )

    predicted_top = set(
        predicted.nlargest(effective_k).index
    )

    return (
        len(actual_top.intersection(predicted_top))
        / effective_k
    )


def create_hybrid_ranking() -> None:
    """
    Combine Ridge predictions with an explicit KEV safeguard.

    Ridge is used for ordinary paths. The explainable baseline
    score is retained for paths containing a CISA KEV entry.
    """

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Model comparison file not found: {INPUT_FILE}"
        )

    dataframe = pd.read_csv(INPUT_FILE)

    required_columns = {
        "path_id",
        "vulnerability_signature",
        "baseline_rank",
        "baseline_risk_score",
        "baseline_risk_level",
        "maximum_cvss",
        "maximum_epss",
        "kev_present",
        "RidgeRegression_prediction",
    }

    missing_columns = (
        required_columns - set(dataframe.columns)
    )

    if missing_columns:
        raise ValueError(
            "Input file is missing columns: "
            f"{sorted(missing_columns)}"
        )

    dataframe["baseline_risk_score"] = pd.to_numeric(
        dataframe["baseline_risk_score"],
        errors="raise",
    )

    dataframe["RidgeRegression_prediction"] = (
        pd.to_numeric(
            dataframe["RidgeRegression_prediction"],
            errors="raise",
        )
    )

    dataframe["kev_present"] = (
        pd.to_numeric(
            dataframe["kev_present"],
            errors="coerce",
        )
        .fillna(0)
        .astype(int)
    )

    dataframe["hybrid_ai_score"] = dataframe[
        "RidgeRegression_prediction"
    ].clip(
        lower=0.0,
        upper=100.0,
    )

    kev_mask = dataframe["kev_present"] == 1

    # Explicit safety rule:
    # AI prediction cannot lower a KEV path below the
    # explainable baseline score.
    dataframe.loc[
        kev_mask,
        "hybrid_ai_score",
    ] = dataframe.loc[
        kev_mask,
        [
            "RidgeRegression_prediction",
            "baseline_risk_score",
        ],
    ].max(axis=1)

    dataframe["score_source"] = "Ridge Regression"

    dataframe.loc[
        kev_mask,
        "score_source",
    ] = "KEV safeguard"

    dataframe["safeguard_applied"] = kev_mask

    dataframe["hybrid_risk_level"] = dataframe[
        "hybrid_ai_score"
    ].apply(risk_level)

    dataframe["hybrid_rank"] = (
        dataframe["hybrid_ai_score"]
        .rank(
            method="min",
            ascending=False,
        )
        .astype(int)
    )

    dataframe["hybrid_absolute_error"] = (
        dataframe["baseline_risk_score"]
        - dataframe["hybrid_ai_score"]
    ).abs()

    dataframe["rank_difference"] = (
        dataframe["baseline_rank"]
        - dataframe["hybrid_rank"]
    ).abs()

    actual = dataframe["baseline_risk_score"]
    hybrid = dataframe["hybrid_ai_score"]

    mae = mean_absolute_error(actual, hybrid)

    rmse = mean_squared_error(
        actual,
        hybrid,
    ) ** 0.5

    r_squared = r2_score(actual, hybrid)

    correlation = rank_correlation(
        actual,
        hybrid,
    )

    top_10 = top_k_overlap(
        actual,
        hybrid,
        k=10,
    )

    maximum_error = dataframe[
        "hybrid_absolute_error"
    ].max()

    kev_error = (
        dataframe.loc[
            kev_mask,
            "hybrid_absolute_error",
        ].mean()
        if kev_mask.any()
        else 0.0
    )

    metrics = pd.DataFrame(
        [
            {
                "model": "Hybrid Ridge with KEV safeguard",
                "paths": len(dataframe),
                "safeguard_paths": int(kev_mask.sum()),
                "mae": mae,
                "rmse": rmse,
                "r2": r_squared,
                "rank_correlation": correlation,
                "top_10_overlap": top_10,
                "maximum_absolute_error": maximum_error,
                "kev_absolute_error": kev_error,
            }
        ]
    )

    dataframe = dataframe.sort_values(
        by=[
            "hybrid_rank",
            "hybrid_ai_score",
        ],
        ascending=[
            True,
            False,
        ],
    )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    dataframe.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    metrics.to_csv(
        METRICS_FILE,
        index=False,
    )

    print("Hybrid AI ranking completed.")
    print()

    print(
        f"Paths ranked: {len(dataframe)}"
    )

    print(
        f"KEV safeguards applied: {int(kev_mask.sum())}"
    )

    print()
    print(f"MAE: {mae:.6f}")
    print(f"RMSE: {rmse:.6f}")
    print(f"R2: {r_squared:.6f}")
    print(f"Rank correlation: {correlation:.6f}")
    print(f"Top-10 overlap: {top_10:.2f}")
    print(f"Maximum error: {maximum_error:.6f}")
    print(f"KEV error: {kev_error:.6f}")

    print()
    print("Top 10 hybrid-ranked paths:")

    print(
        dataframe[
            [
                "hybrid_rank",
                "path_id",
                "vulnerability_signature",
                "hybrid_ai_score",
                "hybrid_risk_level",
                "score_source",
            ]
        ]
        .head(10)
        .to_string(index=False)
    )

    print()
    print(f"Ranked paths: {OUTPUT_FILE}")
    print(f"Hybrid metrics: {METRICS_FILE}")


if __name__ == "__main__":
    create_hybrid_ranking()