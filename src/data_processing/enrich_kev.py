from pathlib import Path
import csv

KEV = Path("data/raw/external/cisa_kev/known_exploited_vulnerabilities.csv")
LINKS = Path("data/processed/lab/vulnerabilities/finding_cve_links.csv")
OUT = Path("data/processed/lab/enrichment/kev_enrichment.csv")

# The CISA KEV dataset is loaded by CVE ID.
with open(KEV, encoding="utf-8-sig") as f:
    kev_data = {
        row["cveID"]: row
        for row in csv.DictReader(f)
    }

# Unique CVEs from the lab dataset are collected.
with open(LINKS, encoding="utf-8") as f:
    lab_cves = sorted({
        row["cve_id"]
        for row in csv.DictReader(f)
    })

rows = []

# Each lab CVE is checked against the KEV catalogue.
for cve_id in lab_cves:
    match = kev_data.get(cve_id)

    rows.append({
        "cve_id": cve_id,
        "in_kev": bool(match),
        "vendor": match["vendorProject"] if match else "",
        "product": match["product"] if match else "",
        "vulnerability_name": match["vulnerabilityName"] if match else "",
        "date_added": match["dateAdded"] if match else "",
        "ransomware_use": match["knownRansomwareCampaignUse"] if match else "",
        "cwes": match["cwes"] if match else "",
    })

# The KEV enrichment table is saved.
OUT.parent.mkdir(parents=True, exist_ok=True)

with open(OUT, "w", encoding="utf-8", newline="") as f:
    fields = [
        "cve_id",
        "in_kev",
        "vendor",
        "product",
        "vulnerability_name",
        "date_added",
        "ransomware_use",
        "cwes",
    ]

    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

matched = sum(row["in_kev"] for row in rows)

print(f"Lab CVEs: {len(rows)}")
print(f"Found in CISA KEV: {matched}")
print(f"Not in CISA KEV: {len(rows) - matched}")