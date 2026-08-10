from pathlib import Path
import csv
import gzip

EPSS = Path("data/raw/external/epss/epss_scores-2026-08-07.csv.gz")
LINKS = Path("data/processed/lab/vulnerabilities/finding_cve_links.csv")
OUT = Path("data/processed/lab/enrichment/epss_enrichment.csv")

# The EPSS dataset is loaded by CVE ID.
with gzip.open(EPSS, "rt", encoding="utf-8") as f:
    metadata = f.readline().strip()
    reader = csv.DictReader(f)
    epss_data = {row["cve"]: row for row in reader}

# Unique CVEs from the lab dataset are collected.
with open(LINKS, encoding="utf-8") as f:
    lab_cves = sorted({row["cve_id"] for row in csv.DictReader(f)})

rows = []

# Each lab CVE is matched with its EPSS score.
for cve_id in lab_cves:
    match = epss_data.get(cve_id)

    rows.append({
        "cve_id": cve_id,
        "epss_found": bool(match),
        "epss": match["epss"] if match else "",
        "percentile": match["percentile"] if match else "",
    })

# The enrichment table is saved.
OUT.parent.mkdir(parents=True, exist_ok=True)

with open(OUT, "w", encoding="utf-8", newline="") as f:
    fields = ["cve_id", "epss_found", "epss", "percentile"]
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

found = sum(row["epss_found"] for row in rows)

print(metadata)
print(f"Lab CVEs: {len(rows)}")
print(f"Found in EPSS: {found}")
print(f"Not found in EPSS: {len(rows) - found}")