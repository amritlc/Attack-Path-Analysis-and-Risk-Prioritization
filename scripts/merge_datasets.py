from __future__ import annotations

import csv
import ipaddress
from collections import defaultdict
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

HOSTS_FILE = PROCESSED_DIR / "hosts.csv"
SERVICES_FILE = PROCESSED_DIR / "services.csv"
VULNERABILITIES_FILE = PROCESSED_DIR / "vulnerabilities.csv"

OUTPUT_FILE = PROCESSED_DIR / "enriched_services.csv"
UNMATCHED_FILE = PROCESSED_DIR / "unmatched_vulnerabilities.csv"
SUMMARY_FILE = PROCESSED_DIR / "integration_summary.csv"


def clean(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def normalize_protocol(value: Any) -> str:
    return clean(value).lower()


def normalize_port(value: Any) -> int | None:
    text = clean(value)

    if not text:
        return None

    try:
        return int(float(text))
    except ValueError:
        return None


def safe_float(value: Any) -> float:
    try:
        return float(clean(value))
    except ValueError:
        return 0.0


def ip_sort_key(value: str) -> tuple[int, int, int, int]:
    try:
        address = ipaddress.ip_address(value)
        return tuple(int(part) for part in str(address).split("."))
    except ValueError:
        return 999, 999, 999, 999


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
        errors="replace",
    ) as file:
        return list(csv.DictReader(file))


def create_empty_vulnerability() -> dict[str, str]:
    return {
        "cvss": "",
        "severity": "",
        "solution_type": "",
        "nvt_name": "",
        "summary": "",
        "specific_result": "",
        "nvt_oid": "",
        "cves": "",
        "timestamp": "",
        "result_id": "",
        "impact": "",
        "solution": "",
        "affected_software_os": "",
        "vulnerability_insight": "",
        "detection_method": "",
        "product_detection_result": "",
        "source_file": "",
    }


def build_output_row(
    host: dict[str, str],
    service: dict[str, str] | None,
    vulnerability: dict[str, str],
    match_status: str,
) -> dict[str, Any]:
    ip_address = clean(
        service.get("ip_address") if service else vulnerability.get("ip_address")
    )

    port = normalize_port(
        service.get("port") if service else vulnerability.get("port")
    )

    protocol = normalize_protocol(
        service.get("protocol") if service else vulnerability.get("protocol")
    )

    cvss = clean(vulnerability.get("cvss"))

    return {
        "ip_address": ip_address,
        "host_hostname": clean(host.get("hostname")),
        "mac_address": clean(host.get("mac_address")),
        "vendor": clean(host.get("vendor")),
        "host_status": clean(host.get("status")),
        "os_guess": clean(host.get("os_guess")),
        "os_accuracy": clean(host.get("os_accuracy")),
        "protocol": protocol,
        "port": port if port is not None else "",
        "service_state": clean(service.get("state")) if service else "",
        "service_name": clean(service.get("service_name")) if service else "",
        "product": clean(service.get("product")) if service else "",
        "version": clean(service.get("version")) if service else "",
        "extra_info": clean(service.get("extra_info")) if service else "",
        "service_cpe": clean(service.get("cpe")) if service else "",
        "has_vulnerability": "yes" if vulnerability.get("nvt_name") else "no",
        "cvss": cvss,
        "severity": clean(vulnerability.get("severity")),
        "solution_type": clean(vulnerability.get("solution_type")),
        "nvt_name": clean(vulnerability.get("nvt_name")),
        "nvt_oid": clean(vulnerability.get("nvt_oid")),
        "cves": clean(vulnerability.get("cves")),
        "summary": clean(vulnerability.get("summary")),
        "specific_result": clean(vulnerability.get("specific_result")),
        "impact": clean(vulnerability.get("impact")),
        "solution": clean(vulnerability.get("solution")),
        "affected_software_os": clean(
            vulnerability.get("affected_software_os")
        ),
        "vulnerability_insight": clean(
            vulnerability.get("vulnerability_insight")
        ),
        "detection_method": clean(
            vulnerability.get("detection_method")
        ),
        "product_detection_result": clean(
            vulnerability.get("product_detection_result")
        ),
        "scan_timestamp": clean(vulnerability.get("timestamp")),
        "result_id": clean(vulnerability.get("result_id")),
        "match_status": match_status,
        "service_source_file": (
            clean(service.get("source_file")) if service else ""
        ),
        "vulnerability_source_file": clean(
            vulnerability.get("source_file")
        ),
    }


def write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    fieldnames: list[str],
) -> None:
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    hosts = read_csv(HOSTS_FILE)
    services = read_csv(SERVICES_FILE)
    vulnerabilities = read_csv(VULNERABILITIES_FILE)

    hosts_by_ip = {
        clean(host.get("ip_address")): host
        for host in hosts
    }

    vulnerabilities_by_service: dict[
        tuple[str, int | None, str],
        list[dict[str, str]],
    ] = defaultdict(list)

    for vulnerability in vulnerabilities:
        key = (
            clean(vulnerability.get("ip_address")),
            normalize_port(vulnerability.get("port")),
            normalize_protocol(vulnerability.get("protocol")),
        )
        vulnerabilities_by_service[key].append(vulnerability)

    output_rows: list[dict[str, Any]] = []
    matched_result_ids: set[str] = set()
    service_keys_with_vulnerabilities: set[
        tuple[str, int | None, str]
    ] = set()

    for service in services:
        ip_address = clean(service.get("ip_address"))
        port = normalize_port(service.get("port"))
        protocol = normalize_protocol(service.get("protocol"))

        key = (ip_address, port, protocol)
        host = hosts_by_ip.get(ip_address, {})
        matches = vulnerabilities_by_service.get(key, [])

        if matches:
            service_keys_with_vulnerabilities.add(key)

            for vulnerability in matches:
                result_id = clean(vulnerability.get("result_id"))

                if result_id:
                    matched_result_ids.add(result_id)

                output_rows.append(
                    build_output_row(
                        host,
                        service,
                        vulnerability,
                        "matched",
                    )
                )
        else:
            output_rows.append(
                build_output_row(
                    host,
                    service,
                    create_empty_vulnerability(),
                    "service_without_vulnerability",
                )
            )

    unmatched_rows: list[dict[str, Any]] = []

    for vulnerability in vulnerabilities:
        result_id = clean(vulnerability.get("result_id"))

        if result_id and result_id in matched_result_ids:
            continue

        ip_address = clean(vulnerability.get("ip_address"))
        host = hosts_by_ip.get(ip_address, {})

        unmatched_row = build_output_row(
            host,
            None,
            vulnerability,
            "vulnerability_without_nmap_service",
        )

        output_rows.append(unmatched_row)
        unmatched_rows.append(unmatched_row)

    output_rows.sort(
        key=lambda row: (
            ip_sort_key(clean(row["ip_address"])),
            int(row["port"]) if str(row["port"]).isdigit() else 0,
            -safe_float(row["cvss"]),
            clean(row["nvt_name"]),
        )
    )

    fieldnames = [
        "ip_address",
        "host_hostname",
        "mac_address",
        "vendor",
        "host_status",
        "os_guess",
        "os_accuracy",
        "protocol",
        "port",
        "service_state",
        "service_name",
        "product",
        "version",
        "extra_info",
        "service_cpe",
        "has_vulnerability",
        "cvss",
        "severity",
        "solution_type",
        "nvt_name",
        "nvt_oid",
        "cves",
        "summary",
        "specific_result",
        "impact",
        "solution",
        "affected_software_os",
        "vulnerability_insight",
        "detection_method",
        "product_detection_result",
        "scan_timestamp",
        "result_id",
        "match_status",
        "service_source_file",
        "vulnerability_source_file",
    ]

    write_csv(OUTPUT_FILE, output_rows, fieldnames)
    write_csv(UNMATCHED_FILE, unmatched_rows, fieldnames)

    service_keys = {
        (
            clean(service.get("ip_address")),
            normalize_port(service.get("port")),
            normalize_protocol(service.get("protocol")),
        )
        for service in services
    }

    summary_rows = [
        {"metric": "hosts", "value": len(hosts)},
        {"metric": "nmap_services", "value": len(services)},
        {
            "metric": "openvas_vulnerabilities",
            "value": len(vulnerabilities),
        },
        {
            "metric": "services_with_vulnerabilities",
            "value": len(service_keys_with_vulnerabilities),
        },
        {
            "metric": "services_without_vulnerabilities",
            "value": len(service_keys - service_keys_with_vulnerabilities),
        },
        {
            "metric": "vulnerabilities_without_nmap_service",
            "value": len(unmatched_rows),
        },
        {
            "metric": "integrated_output_rows",
            "value": len(output_rows),
        },
    ]

    write_csv(
        SUMMARY_FILE,
        summary_rows,
        ["metric", "value"],
    )

    print(f"Hosts loaded: {len(hosts)}")
    print(f"Nmap services loaded: {len(services)}")
    print(f"OpenVAS findings loaded: {len(vulnerabilities)}")
    print(f"Integrated rows written: {len(output_rows)}")
    print(f"Unmatched vulnerabilities: {len(unmatched_rows)}")
    print(f"Output: {OUTPUT_FILE}")
    print(f"Output: {UNMATCHED_FILE}")
    print(f"Output: {SUMMARY_FILE}")


if __name__ == "__main__":
    main()