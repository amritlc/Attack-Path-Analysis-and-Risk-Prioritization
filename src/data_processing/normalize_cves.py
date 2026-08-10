from pathlib import Path
import csv
import re

INPUT = Path("data/processed/lab/vulnerabilities/openvas_findings.csv")
OUTPUT = Path("data/processed/lab/vulnerabilities/finding_cve_links.csv")

links = []
findings = set()
with_cve = set()

# extract valid CVEs from each OpenVAS finding.
with open(INPUT, encoding="utf-8") as f:
    for row in csv.DictReader(f):
        result_id = row["result_id"]
        findings.add(result_id)

        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", row["cves"], re.I):
            links.append({"result_id": result_id, "cve_id": cve.upper()})
            with_cve.add(result_id)

# normalised CVE links are saved.
with open(OUTPUT, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["result_id", "cve_id"])
    writer.writeheader()
    writer.writerows(links)

unique_cves = {row["cve_id"] for row in links}

print(f"Findings with CVE: {len(with_cve)}")
print(f"Findings without CVE: {len(findings - with_cve)}")
print(f"CVE links: {len(links)}")
print(f"Unique CVEs: {len(unique_cves)}")