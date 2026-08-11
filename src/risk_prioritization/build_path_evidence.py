from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab")

features = pd.read_csv(
    BASE / "attack_paths/path_features.csv"
)

assets = pd.read_csv(
    "data/manual/assets.csv"
)

OUT = BASE / "risk/path_evidence.csv"

target = assets[assets["target"] == True].iloc[0]

data = features.copy()

# Missing vulnerability evidence is separated from real zero values.
no_evidence = data["compromise_steps"] == 0

columns = [
    "max_cvss",
    "mean_cvss",
    "max_epss",
    "mean_epss",
]

data.loc[no_evidence, columns] = pd.NA

# Scenario context is recorded without numerical weighting.
data["target_asset"] = target["asset_name"]
data["target_criticality"] = target["criticality"]

result = data[
    [
        "path_id",
        "hop_count",
        "compromise_steps",
        "total_vulnerabilities",
        "max_cvss",
        "mean_cvss",
        "max_epss",
        "mean_epss",
        "kev_count",
        "target_asset",
        "target_criticality",
        "asset_path",
    ]
]

result.to_csv(OUT, index=False)

print(result.to_string(index=False))