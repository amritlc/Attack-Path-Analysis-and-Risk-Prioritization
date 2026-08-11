from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab/risk")

baseline = pd.read_csv(BASE / "cvss_baseline.csv")
pareto = pd.read_csv(BASE / "pareto_prioritization.csv")

# Baseline and multi-evidence results are joined.
data = baseline.merge(
    pareto[
        [
            "path_id",
            "compromise_steps",
            "bottleneck_cvss",
            "bottleneck_epss",
            "kev_coverage",
            "evidence_front",
        ]
    ],
    on="path_id",
    how="left",
)

# Direct exposure is kept separate from vulnerability ranking.
data["analysis_type"] = "vulnerability_supported"

data.loc[
    data["compromise_steps"] == 0,
    "analysis_type"
] = "direct_target_exposure"

result = data[
    [
        "path_id",
        "baseline_cvss",
        "baseline_rank",
        "bottleneck_cvss",
        "bottleneck_epss",
        "kev_coverage",
        "evidence_front",
        "analysis_type",
        "asset_path",
    ]
]

result.to_csv(
    BASE / "prioritization_comparison.csv",
    index=False,
)

print(result.to_string(index=False))