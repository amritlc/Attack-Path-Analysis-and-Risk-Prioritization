from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab/risk")

baseline = pd.read_csv(BASE / "cvss_baseline.csv")
pareto = pd.read_csv(BASE / "pareto_prioritization.csv")
ablation = pd.read_csv(BASE / "feature_ablation.csv")
comparison = pd.read_csv(BASE / "prioritization_comparison.csv")

checks = {}

# The CVSS baseline must keep the expected tie.
rank_one = set(
    baseline[baseline["baseline_rank"] == 1]["path_id"]
)

checks["baseline_rank_one_tie"] = (
    rank_one == {"P002", "P003", "P005"}
)

# P002 must form the first evidence front.
front_one = set(
    pareto[pareto["evidence_front"] == 1]["path_id"]
)

checks["p002_is_front_one"] = (
    front_one == {"P002"}
)

# P003 and P005 must remain tied.
front_two = set(
    pareto[pareto["evidence_front"] == 2]["path_id"]
)

checks["p003_p005_tied"] = (
    front_two == {"P003", "P005"}
)

# P004 must form the third evidence front.
front_three = set(
    pareto[pareto["evidence_front"] == 3]["path_id"]
)

checks["p004_is_front_three"] = (
    front_three == {"P004"}
)

# P001 must remain outside vulnerability ranking.
p001 = comparison[
    comparison["path_id"] == "P001"
].iloc[0]

checks["p001_is_direct_exposure"] = (
    p001["analysis_type"] == "direct_target_exposure"
)

checks["p001_has_no_evidence_front"] = (
    pd.isna(p001["evidence_front"])
)

# P002 must remain Front 1 in every ablation.
p002 = ablation[
    ablation["path_id"] == "P002"
].iloc[0]

checks["p002_stable_in_ablation"] = all(
    p002[column] == 1
    for column in [
        "full",
        "without_cvss",
        "without_epss",
        "without_kev",
    ]
)

# KEV removal must remove the P004 distinction.
no_kev = ablation.set_index("path_id")["without_kev"]

checks["kev_ablation_effect"] = (
    no_kev["P003"] ==
    no_kev["P004"] ==
    no_kev["P005"]
)

for name, passed in checks.items():
    print(f"{name}: {passed}")

if not all(checks.values()):
    raise ValueError("Prioritisation validation failed.")

print("Prioritisation validation passed.")