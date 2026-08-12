from pathlib import Path
import json
import pandas as pd

BASE = Path("data/processed/lab/risk")
MODEL = Path("models/cve2attack")

predictions = pd.read_csv(
    BASE / "lab_attack_predictions.csv"
)

cve_summary = pd.read_csv(
    BASE / "lab_attack_prediction_summary.csv"
)

context = pd.read_csv(
    BASE / "path_attack_context.csv"
)

path_summary = pd.read_csv(
    BASE / "path_attack_context_summary.csv"
)

with open(
    MODEL / "threshold.json",
    encoding="utf-8",
) as file:
    threshold = json.load(file)["threshold"]

checks = {}

# All 77 lab CVEs must be analysed.
checks["all_lab_cves_present"] = (
    len(cve_summary) == 77
)

# Provenance counts must match the completed audit.
checks["train_seen_count"] = (
    (cve_summary["provenance"] == "train_seen").sum() == 4
)

checks["test_seen_count"] = (
    (cve_summary["provenance"] == "test_seen").sum() == 0
)

checks["unseen_count"] = (
    (cve_summary["provenance"] == "unseen").sum() == 73
)

# Every retained prediction must meet the selected threshold.
checks["predictions_meet_threshold"] = (
    predictions["model_probability"] >= threshold
).all()

# Model probabilities must remain valid.
checks["probabilities_valid"] = (
    predictions["model_probability"]
    .between(0, 1)
    .all()
)

# All five attack paths must have summary rows.
checks["all_paths_present"] = (
    set(path_summary["path_id"])
    == {"P001", "P002", "P003", "P004", "P005"}
)

# Predicted CVEs cannot exceed observed CVEs.
checks["prediction_counts_valid"] = (
    path_summary["predicted_cve_count"]
    <= path_summary["observed_cve_count"]
).all()

# Coverage must match the observed counts.
coverage_ok = True

for _, row in path_summary.iterrows():
    observed = row["observed_cve_count"]
    predicted = row["predicted_cve_count"]

    if observed == 0:
        continue

    expected = round(
        predicted / observed,
        4,
    )

    if row["prediction_coverage"] != expected:
        coverage_ok = False

checks["coverage_correct"] = coverage_ok

# P001 must remain outside AI vulnerability context.
p001 = path_summary[
    path_summary["path_id"] == "P001"
].iloc[0]

checks["p001_has_no_ai_context"] = (
    p001["observed_cve_count"] == 0
    and p001["predicted_cve_count"] == 0
    and p001["predicted_technique_count"] == 0
)

# Context rows must contain real predictions only.
checks["context_not_empty"] = len(context) > 0

checks["context_has_no_missing_techniques"] = (
    context["attack_technique"].notna().all()
)

for name, passed in checks.items():
    print(f"{name}: {passed}")

if not all(checks.values()):
    raise ValueError("AI context validation failed.")

print("AI context validation passed.")