from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab")
MANUAL = Path("data/manual")
OUT = BASE / "master_vulnerabilities.csv"

findings = pd.read_csv(BASE / "vulnerabilities/integrated_findings.csv")
links = pd.read_csv(BASE / "vulnerabilities/finding_cve_links.csv")
nvd = pd.read_csv(BASE / "enrichment/nvd_enrichment.csv")
epss = pd.read_csv(BASE / "enrichment/epss_enrichment.csv")
kev = pd.read_csv(BASE / "enrichment/kev_enrichment.csv")
assets = pd.read_csv(MANUAL / "assets.csv")

# Clear names are used before the datasets are joined.
findings = findings.rename(columns={
    "cvss": "openvas_cvss",
    "severity": "openvas_severity",
    "product": "service_product"
})

nvd = nvd.rename(columns={
    "severity": "nvd_severity"
})

kev = kev.rename(columns={
    "vendor": "kev_vendor",
    "product": "kev_product"
})

# CVEs are attached to their OpenVAS findings.
data = findings.merge(links, on="result_id", how="left")

# Vulnerability intelligence is added by CVE ID.
data = data.merge(nvd, on="cve_id", how="left")
data = data.merge(epss, on="cve_id", how="left")
data = data.merge(kev, on="cve_id", how="left")

# Asset context is added by IP address.
data = data.merge(assets, on="ip", how="left")

# Ports are stored without decimal values.
data["port"] = data["port"].astype("Int64")

data.to_csv(OUT, index=False)

print(f"Master rows: {len(data)}")
print(f"Unique findings: {data['result_id'].nunique()}")
print(f"Unique CVEs: {data['cve_id'].nunique()}")
print(f"Unique assets: {data['ip'].nunique()}")