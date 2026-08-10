from pathlib import Path
import csv

RAW = Path("data/raw/openvas")
OUT = Path("data/processed/lab/vulnerabilities/openvas_findings.csv")

findings = []

#  read every OpenVAS CSV export.
for file in RAW.rglob("*.csv"):
    with open(file, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            findings.append({
                "result_id": row["Result ID"],
                "ip": row["IP"],
                "hostname": row["Hostname"],
                "port": row["Port"],
                "protocol": row["Port Protocol"],
                "cvss": row["CVSS"],
                "severity": row["Severity"],
                "nvt_name": row["NVT Name"],
                "nvt_oid": row["NVT OID"],
                "cves": row["CVEs"],
                "timestamp": row["Timestamp"],
                "source_file": file.name,
            })

OUT.parent.mkdir(parents=True, exist_ok=True)

#  combined findings are saved.
with open(OUT, "w", encoding="utf-8", newline="") as f:
    fields = findings[0].keys()
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(findings)

print(f"OpenVAS findings: {len(findings)}")