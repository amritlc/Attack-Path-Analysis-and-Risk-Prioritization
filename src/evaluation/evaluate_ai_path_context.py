from pathlib import Path
import pandas as pd

SOURCE = Path(
    "data/processed/lab/risk/path_attack_context_summary.csv"
)

CVE_SOURCE = Path(
    "data/processed/lab/risk/lab_attack_prediction_summary.csv"
)

OUT = Path(
    "data/processed/lab/evaluation"
)

OUT.mkdir(parents=True, exist_ok=True)

paths = pd.read_csv(SOURCE)
cves = pd.read_csv(CVE_SOURCE)

# Lab-level prediction coverage is calculated.
total_cves = len(cves)

predicted_cves = (
    cves["prediction_count"] > 0
).sum()

lab_coverage = (
    predicted_cves / total_cves
)

lab_summary = pd.DataFrame([
    {
        "lab_cve_count": total_cves,
        "cves_with_predictions": int(
            predicted_cves
        ),
        "cves_without_predictions": int(
            total_cves - predicted_cves
        ),
        "lab_prediction_coverage": lab_coverage,
    }
])

# Path-level AI coverage is preserved.
path_summary = paths[
    [
        "path_id",
        "observed_cve_count",
        "predicted_cve_count",
        "prediction_coverage",
        "predicted_technique_count",
    ]
].copy()

lab_summary.to_csv(
    OUT / "ai_lab_coverage.csv",
    index=False,
)

path_summary.to_csv(
    OUT / "ai_path_coverage.csv",
    index=False,
)

print("Lab CVE coverage:")
print(lab_summary.to_string(index=False))

print()
print("Attack-path AI coverage:")
print(path_summary.to_string(index=False))