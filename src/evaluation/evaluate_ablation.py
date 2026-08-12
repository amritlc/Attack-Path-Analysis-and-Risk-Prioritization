from pathlib import Path
import pandas as pd

SOURCE = Path(
    "data/processed/lab/risk/feature_ablation.csv"
)

OUT = Path(
    "data/processed/lab/evaluation"
)

OUT.mkdir(parents=True, exist_ok=True)

data = pd.read_csv(SOURCE)

experiments = {
    "without_cvss": "CVSS",
    "without_epss": "EPSS",
    "without_kev": "KEV",
}

rows = []

# Each single-feature removal is compared with the full result.
for column, evidence in experiments.items():
    changed = data[
        data[column] != data["full"]
    ]

    front1 = data[
        data[column] == 1
    ]["path_id"].tolist()

    rows.append({
        "removed_evidence": evidence,
        "changed_path_count": len(changed),
        "changed_paths": " | ".join(
            changed["path_id"].tolist()
        ),
        "front1_paths": " | ".join(front1),
        "distinct_front_count": data[column].nunique(),
    })

summary = pd.DataFrame(rows)

summary.to_csv(
    OUT / "ablation_summary.csv",
    index=False,
)

data.to_csv(
    OUT / "ablation_path_results.csv",
    index=False,
)

print("Path-level ablation:")
print(data.to_string(index=False))

print()
print("Ablation summary:")
print(summary.to_string(index=False))