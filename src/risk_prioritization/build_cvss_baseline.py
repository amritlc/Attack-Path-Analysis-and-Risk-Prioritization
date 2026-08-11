from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab")
INPUT = BASE / "attack_paths/path_features.csv"
OUT = BASE / "risk"

OUT.mkdir(parents=True, exist_ok=True)

data = pd.read_csv(INPUT)

# CVSS is used as the traditional severity baseline.
data["baseline_cvss"] = data["max_cvss"]

# A direct reach path has no vulnerability-based CVSS evidence.
data.loc[
    data["compromise_steps"] == 0,
    "baseline_cvss"
] = pd.NA

# Higher CVSS values are ranked first.
data["baseline_rank"] = (
    data["baseline_cvss"]
    .rank(method="dense", ascending=False)
    .astype("Int64")
)

result = data[
    [
        "path_id",
        "baseline_cvss",
        "baseline_rank",
        "asset_path",
    ]
]

result.to_csv(OUT / "cvss_baseline.csv", index=False)

print(result.to_string(index=False))