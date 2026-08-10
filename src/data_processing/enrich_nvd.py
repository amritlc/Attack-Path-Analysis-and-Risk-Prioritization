from pathlib import Path
import csv
import json

NVD = Path("data/raw/external/nvd")
LINKS = Path("data/processed/lab/vulnerabilities/finding_cve_links.csv")
OUT = Path("data/processed/lab/enrichment/nvd_enrichment.csv")

nvd_data = {}

# NVD JSON files are read and indexed by CVE ID.
for file in NVD.glob("*.json"):
    with open(file, encoding="utf-8") as f:
        data = json.load(f)

    if not data.get("vulnerabilities"):
        continue

    cve = data["vulnerabilities"][0]["cve"]
    metrics = cve.get("metrics", {})

    metric = {}
    for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if metrics.get(key):
            metric = metrics[key][0]
            break

    cvss = metric.get("cvssData", {})

    cwe = ""
    for weakness in cve.get("weaknesses", []):
        for item in weakness.get("description", []):
            if item.get("lang") == "en":
                cwe = item.get("value", "")
                break

    nvd_data[cve["id"]] = {
        "cvss_version": cvss.get("version", ""),
        "cvss_score": cvss.get("baseScore", ""),
        "severity": cvss.get("baseSeverity", metric.get("baseSeverity", "")),
        "vector": cvss.get("vectorString", ""),
        "attack_vector": cvss.get(
    "attackVector",
    cvss.get("accessVector", "")
),
"attack_complexity": cvss.get(
    "attackComplexity",
    cvss.get("accessComplexity", "")
),
        "privileges_required": cvss.get("privilegesRequired", ""),
        "user_interaction": cvss.get("userInteraction", ""),
        "cwe": cwe,
    }

# Unique CVEs from the lab dataset are collected.
with open(LINKS, encoding="utf-8") as f:
    lab_cves = sorted({row["cve_id"] for row in csv.DictReader(f)})

rows = []

# Each lab CVE is matched with its NVD record.
for cve_id in lab_cves:
    values = nvd_data.get(cve_id, {})

    rows.append({
        "cve_id": cve_id,
        "nvd_found": bool(values),
        **values,
    })

# The enrichment table is saved.
OUT.parent.mkdir(parents=True, exist_ok=True)

fields = [
    "cve_id", "nvd_found", "cvss_version", "cvss_score",
    "severity", "vector", "attack_vector", "attack_complexity",
    "privileges_required", "user_interaction", "cwe"
]

with open(OUT, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

found = sum(row["nvd_found"] for row in rows)
with_cvss = sum(bool(row.get("cvss_score")) for row in rows)

print(f"Lab CVEs: {len(rows)}")
print(f"Found in NVD: {found}")
print(f"Not found in NVD: {len(rows) - found}")
print(f"CVEs with CVSS: {with_cvss}")
print(f"CVEs without CVSS: {len(rows) - with_cvss}")