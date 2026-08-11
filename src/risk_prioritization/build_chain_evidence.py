from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab")
PATHS = BASE / "attack_paths"
OUT = BASE / "risk"

steps = pd.read_csv(PATHS / "path_steps.csv")
vulns = pd.read_csv(BASE / "master_vulnerabilities.csv")
paths = pd.read_csv(PATHS / "attack_paths.csv")

# A service identifier is created for matching.
vulns["service_node"] = (
    "service:" + vulns["ip"].astype(str) + ":" +
    vulns["port"].astype("Int64").astype(str) + ":" +
    vulns["protocol"].astype(str)
)

rows = []

# Only candidate-compromise steps are analysed.
for _, step in steps[
    steps["step_type"] == "candidate_compromise"
].iterrows():

    data = vulns[
        vulns["service_node"] == step["service"]
    ].copy()

    data["vuln_id"] = data["cve_id"].fillna(
        data["result_id"]
    )

    # One row is retained for each vulnerability.
    data = data.drop_duplicates("vuln_id")

    # NVD CVSS is preferred and OpenVAS CVSS is used as fallback.
    data["risk_cvss"] = data["cvss_score"].fillna(
        data["openvas_cvss"]
    )

    kev = (
        data["in_kev"]
        .astype(str)
        .str.lower()
        .eq("true")
        .any()
    )

    rows.append({
        "path_id": step["path_id"],
        "step": step["step"],
        "service": step["service"],
        "step_max_cvss": data["risk_cvss"].max(),
        "step_max_epss": data["epss"].max(),
        "step_has_kev": kev,
    })

step_data = pd.DataFrame(rows)

step_data.to_csv(
    OUT / "step_evidence.csv",
    index=False
)

summary = []

for _, path in paths.iterrows():
    data = step_data[
        step_data["path_id"] == path["path_id"]
    ]

    if data.empty:
        summary.append({
            "path_id": path["path_id"],
            "compromise_steps": 0,
            "bottleneck_cvss": pd.NA,
            "bottleneck_epss": pd.NA,
            "kev_steps": 0,
            "kev_coverage": pd.NA,
        })
        continue

    count = len(data)
    kev_steps = int(data["step_has_kev"].sum())

    summary.append({
        "path_id": path["path_id"],
        "compromise_steps": count,
        "bottleneck_cvss": data["step_max_cvss"].min(),
        "bottleneck_epss": data["step_max_epss"].min(),
        "kev_steps": kev_steps,
        "kev_coverage": round(kev_steps / count, 4),
    })

pd.DataFrame(summary).to_csv(
    OUT / "chain_evidence.csv",
    index=False
)

print("Step evidence:")
print(step_data.to_string(index=False))

print("\nChain evidence:")
print(pd.DataFrame(summary).to_string(index=False))