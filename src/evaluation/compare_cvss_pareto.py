from pathlib import Path
import pandas as pd

SOURCE = Path(
    "data/processed/lab/risk/prioritization_comparison.csv"
)

OUT = Path(
    "data/processed/lab/evaluation"
)

OUT.mkdir(parents=True, exist_ok=True)

data = pd.read_csv(SOURCE)

# Only vulnerability-supported paths are compared.
supported = data[
    data["analysis_type"] == "vulnerability_supported"
].copy()

# Highest-priority groups are identified.
best_cvss_rank = supported["baseline_rank"].min()
best_pareto_front = supported["evidence_front"].min()

cvss_top = supported[
    supported["baseline_rank"] == best_cvss_rank
]

pareto_top = supported[
    supported["evidence_front"] == best_pareto_front
]

# Path-level comparison is preserved.
comparison = supported[
    [
        "path_id",
        "baseline_cvss",
        "baseline_rank",
        "bottleneck_cvss",
        "bottleneck_epss",
        "kev_coverage",
        "evidence_front",
    ]
].sort_values(
    ["evidence_front", "path_id"]
)

comparison.to_csv(
    OUT / "cvss_vs_pareto_paths.csv",
    index=False,
)

# Descriptive prioritisation metrics are calculated.
summary = pd.DataFrame([
    {
        "vulnerability_supported_paths": len(supported),
        "cvss_top_group_size": len(cvss_top),
        "pareto_front1_size": len(pareto_top),
        "top_group_reduction": (
            len(cvss_top) - len(pareto_top)
        ),
        "cvss_top_paths": " | ".join(
            cvss_top["path_id"].tolist()
        ),
        "pareto_front1_paths": " | ".join(
            pareto_top["path_id"].tolist()
        ),
    }
])

summary.to_csv(
    OUT / "cvss_pareto_summary.csv",
    index=False,
)

print("Path comparison:")
print(comparison.to_string(index=False))

print()
print("Prioritisation summary:")
print(summary.to_string(index=False))