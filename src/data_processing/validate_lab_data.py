from pathlib import Path
import json
import pandas as pd

BASE = Path("data/processed/lab")
OUT = BASE / "quality"
OUT.mkdir(parents=True, exist_ok=True)

hosts = pd.read_csv(BASE / "inventory/hosts.csv")
services = pd.read_csv(BASE / "inventory/services.csv")
findings = pd.read_csv(BASE / "vulnerabilities/integrated_findings.csv")
links = pd.read_csv(BASE / "vulnerabilities/finding_cve_links.csv")
nvd = pd.read_csv(BASE / "enrichment/nvd_enrichment.csv")
epss = pd.read_csv(BASE / "enrichment/epss_enrichment.csv")
kev = pd.read_csv(BASE / "enrichment/kev_enrichment.csv")
master = pd.read_csv(BASE / "master_vulnerabilities.csv")

# Important quality groups are selected.
unmatched = findings[findings["match_type"] == "unmatched_service"]
without_cve = findings[~findings["result_id"].isin(links["result_id"])]

matched_keys = findings[findings["match_type"] == "service_match"][
    ["ip", "port", "protocol"]
].drop_duplicates()

services_without = services.merge(
    matched_keys,
    on=["ip", "port", "protocol"],
    how="left",
    indicator=True
)

services_without = services_without[
    services_without["_merge"] == "left_only"
].drop(columns="_merge")

# Quality details are saved.
unmatched.to_csv(OUT / "unmatched_service_findings.csv", index=False)
without_cve.to_csv(OUT / "findings_without_cve.csv", index=False)
services_without.to_csv(OUT / "services_without_findings.csv", index=False)

summary = {
    "hosts": len(hosts),
    "services": len(services),
    "openvas_findings": findings["result_id"].nunique(),
    "findings_with_cve": links["result_id"].nunique(),
    "findings_without_cve": len(without_cve),
    "cve_links": len(links),
    "unique_cves": links["cve_id"].nunique(),
    "nvd_matches": int(nvd["nvd_found"].sum()),
    "epss_matches": int(epss["epss_found"].sum()),
    "kev_matches": int(kev["in_kev"].sum()),
    "unmatched_service_findings": len(unmatched),
    "services_without_findings": len(services_without),
    "master_rows": len(master),
    "exact_duplicate_rows": int(master.duplicated().sum()),
}

# The summary is saved as JSON.
with open(OUT / "processing_summary.json", "w") as f:
    json.dump(summary, f, indent=2)

for key, value in summary.items():
    print(f"{key}: {value}")