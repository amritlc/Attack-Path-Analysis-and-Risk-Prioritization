from pathlib import Path
import csv

SERVICES = Path("data/processed/lab/inventory/services.csv")
FINDINGS = Path("data/processed/lab/vulnerabilities/openvas_findings.csv")
OUTPUT = Path("data/processed/lab/vulnerabilities/integrated_findings.csv")

# load Nmap services by IP, port and protocol.
services = {}

with open(SERVICES, encoding="utf-8") as f:
    for row in csv.DictReader(f):
        key = (row["ip"], row["port"], row["protocol"])
        services[key] = row

results = []
matched_services = set()

# Each OpenVAS finding is matched to an Nmap service.
with open(FINDINGS, encoding="utf-8") as f:
    for finding in csv.DictReader(f):

        key = (
            finding["ip"],
            finding["port"],
            finding["protocol"]
        )

        service = services.get(key)

        if not finding["port"]:
            match_type = "host_level"
        elif service:
            match_type = "service_match"
            matched_services.add(key)
        else:
            match_type = "unmatched_service"

        results.append({
            "result_id": finding["result_id"],
            "ip": finding["ip"],
            "port": finding["port"],
            "protocol": finding["protocol"],
            "service": service["service"] if service else "",
            "product": service["product"] if service else "",
            "version": service["version"] if service else "",
            "cvss": finding["cvss"],
            "severity": finding["severity"],
            "nvt_name": finding["nvt_name"],
            "cves": finding["cves"],
            "match_type": match_type,
        })

# The integrated findings are saved.
with open(OUTPUT, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

service_matches = sum(r["match_type"] == "service_match" for r in results)
host_level = sum(r["match_type"] == "host_level" for r in results)
unmatched = sum(r["match_type"] == "unmatched_service" for r in results)

print(f"Total findings: {len(results)}")
print(f"Service-matched findings: {service_matches}")
print(f"Host-level findings: {host_level}")
print(f"Unmatched service findings: {unmatched}")
print(f"Nmap services with findings: {len(matched_services)}")
print(f"Nmap services without findings: {len(services) - len(matched_services)}")