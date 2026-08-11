from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab")
PATHS = BASE / "attack_paths"

paths = pd.read_csv(PATHS / "attack_paths.csv")
steps = pd.read_csv(PATHS / "attack_steps.csv")
vulns = pd.read_csv(BASE / "master_vulnerabilities.csv")

details = []
summary = []

# A service identifier is created for matching.
vulns["service_node"] = (
    "service:" + vulns["ip"].astype(str) + ":" +
    vulns["port"].astype("Int64").astype(str) + ":" +
    vulns["protocol"].astype(str)
)

for _, path_row in paths.iterrows():
    assets = path_row["asset_path"].split(" > ")

    path_cvss = []
    path_epss = []
    kev_count = 0
    total_vulns = 0
    compromise_steps = 0

    for order in range(len(assets) - 1):
        source = assets[order]
        destination = assets[order + 1]

        step = steps[
            (steps["source"] == source) &
            (steps["destination"] == destination)
        ].iloc[0]

        service_vulns = vulns[
            vulns["service_node"] == step["service"]
        ].copy()

        # Vulnerabilities are counted only for compromise steps.
        if step["step_type"] == "candidate_compromise":
            compromise_steps += 1

            service_vulns["vuln_id"] = service_vulns["cve_id"].fillna(
                service_vulns["result_id"]
            )

            service_vulns = service_vulns.drop_duplicates("vuln_id")

            # NVD CVSS is preferred and OpenVAS CVSS is used as fallback.
            service_vulns["risk_cvss"] = service_vulns["cvss_score"].fillna(
                service_vulns["openvas_cvss"]
            )

            path_cvss.extend(service_vulns["risk_cvss"].dropna().tolist())
            path_epss.extend(service_vulns["epss"].dropna().tolist())
            kev_count += service_vulns["in_kev"].fillna(False).sum()
            total_vulns += len(service_vulns)

        details.append({
            "path_id": path_row["path_id"],
            "step": order + 1,
            "source": source,
            "destination": destination,
            "service": step["service"],
            "step_type": step["step_type"],
            "vulnerability_count": int(step["vulnerability_count"]),
        })

    summary.append({
        "path_id": path_row["path_id"],
        "hop_count": path_row["hop_count"],
        "compromise_steps": compromise_steps,
        "total_vulnerabilities": total_vulns,
        "max_cvss": max(path_cvss) if path_cvss else 0,
        "mean_cvss": round(sum(path_cvss) / len(path_cvss), 4) if path_cvss else 0,
        "max_epss": max(path_epss) if path_epss else 0,
        "mean_epss": round(sum(path_epss) / len(path_epss), 4) if path_epss else 0,
        "kev_count": int(kev_count),
        "asset_path": path_row["asset_path"],
    })

pd.DataFrame(details).to_csv(PATHS / "path_steps.csv", index=False)
pd.DataFrame(summary).to_csv(PATHS / "path_features.csv", index=False)

print(f"Paths processed: {len(summary)}")
print(f"Path steps: {len(details)}")