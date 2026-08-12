from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab")
RISK = BASE / "risk"
PATHS = BASE / "attack_paths"

steps = pd.read_csv(
    PATHS / "path_steps.csv"
)

vulns = pd.read_csv(
    BASE / "master_vulnerabilities.csv"
)

predictions = pd.read_csv(
    RISK / "lab_attack_predictions.csv"
)

# A service identifier is created for matching.
vulns["service_node"] = (
    "service:"
    + vulns["ip"].astype(str)
    + ":"
    + vulns["port"].astype("Int64").astype(str)
    + ":"
    + vulns["protocol"].astype(str)
)

context_rows = []
summary_rows = []

path_ids = sorted(
    steps["path_id"].unique()
)

for path_id in path_ids:
    path_steps = steps[
        (steps["path_id"] == path_id)
        & (steps["step_type"] == "candidate_compromise")
    ]

    observed_cves = set()
    predicted_cves = set()
    techniques = set()

    for _, step in path_steps.iterrows():
        service_vulns = vulns[
            vulns["service_node"] == step["service"]
        ]

        cves = set(
            service_vulns["cve_id"]
            .dropna()
            .unique()
        )

        observed_cves.update(cves)

        step_predictions = predictions[
            predictions["cve_id"].isin(cves)
        ]

        for _, prediction in step_predictions.iterrows():
            predicted_cves.add(
                prediction["cve_id"]
            )

            techniques.add(
                prediction["attack_technique"]
            )

            context_rows.append({
                "path_id": path_id,
                "step": step["step"],
                "source": step["source"],
                "destination": step["destination"],
                "service": step["service"],
                "cve_id": prediction["cve_id"],
                "cve_provenance": prediction["provenance"],
                "attack_technique": prediction["attack_technique"],
                "model_probability": prediction["model_probability"],
            })

    observed_count = len(observed_cves)
    predicted_count = len(predicted_cves)

    coverage = (
        predicted_count / observed_count
        if observed_count
        else pd.NA
    )

    summary_rows.append({
        "path_id": path_id,
        "observed_cve_count": observed_count,
        "predicted_cve_count": predicted_count,
        "prediction_coverage": (
            round(coverage, 4)
            if pd.notna(coverage)
            else pd.NA
        ),
        "predicted_technique_count": len(techniques),
        "predicted_techniques": " | ".join(
            sorted(techniques)
        ),
    })

context = pd.DataFrame(context_rows)
summary = pd.DataFrame(summary_rows)

context.to_csv(
    RISK / "path_attack_context.csv",
    index=False,
)

summary.to_csv(
    RISK / "path_attack_context_summary.csv",
    index=False,
)

print(f"Path-technique links: {len(context)}")
print()
print("Path ATT&CK context:")
print(summary.to_string(index=False))