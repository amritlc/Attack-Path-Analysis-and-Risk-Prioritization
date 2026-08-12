from pathlib import Path
import pandas as pd

SOURCE = Path(
    "data/processed/lab/master_vulnerabilities.csv"
)

OUT = Path(
    "data/processed/lab/evaluation"
)

OUT.mkdir(parents=True, exist_ok=True)

data = pd.read_csv(SOURCE)

# Basic host information is preserved.
hosts = (
    data[
        [
            "ip",
            "asset_name",
            "role",
            "criticality",
            "target",
        ]
    ]
    .drop_duplicates()
    .copy()
)

# Unique scanner findings are counted.
findings = (
    data.groupby("ip")["result_id"]
    .nunique()
    .rename("finding_count")
)

# Unique CVEs are counted.
cves = (
    data.groupby("ip")["cve_id"]
    .nunique()
    .rename("cve_count")
)

# Scanner CVSS evidence is retained.
openvas_cvss = (
    data.groupby("ip")["openvas_cvss"]
    .max()
    .rename("max_openvas_cvss")
)

# NVD CVSS evidence is retained.
nvd_cvss = (
    data.groupby("ip")["cvss_score"]
    .max()
    .rename("max_cvss")
)

# EPSS evidence is retained.
epss = (
    data.groupby("ip")["epss"]
    .max()
    .rename("max_epss")
)

# Unique KEV CVEs are counted.
kev_data = data[
    data["in_kev"]
    .astype(str)
    .str.lower()
    .eq("true")
]

kev = (
    kev_data.groupby("ip")["cve_id"]
    .nunique()
    .rename("kev_cve_count")
)

baseline = (
    hosts
    .merge(findings, on="ip", how="left")
    .merge(cves, on="ip", how="left")
    .merge(openvas_cvss, on="ip", how="left")
    .merge(nvd_cvss, on="ip", how="left")
    .merge(epss, on="ip", how="left")
    .merge(kev, on="ip", how="left")
)

baseline["kev_cve_count"] = (
    baseline["kev_cve_count"]
    .fillna(0)
    .astype(int)
)

baseline["has_kev"] = (
    baseline["kev_cve_count"] > 0
)

baseline = baseline.sort_values("ip")

baseline.to_csv(
    OUT / "host_baseline.csv",
    index=False,
)

print(baseline.to_string(index=False))