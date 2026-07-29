from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "openvas"
OUTPUT_DIR = PROJECT_ROOT / "data" / "processed"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def clean_text(value: str | None) -> str:
    """Remove unnecessary whitespace while preserving readable text."""
    if not value:
        return ""

    return " ".join(value.split())


def parse_port(value: str | None) -> int | str:
    if not value:
        return ""

    try:
        return int(value)
    except ValueError:
        return value.strip()


def parse_cvss(value: str | None) -> float | str:
    if not value:
        return ""

    try:
        return float(value)
    except ValueError:
        return ""


def extract_cves(value: str | None) -> str:
    """Extract and normalize CVE identifiers."""
    if not value or value.strip().upper() == "NOCVE":
        return ""

    matches = {
        match.upper()
        for match in CVE_PATTERN.findall(value)
    }

    return ";".join(sorted(matches))


def parse_openvas_file(csv_file: Path) -> list[dict]:
    records: list[dict] = []

    with csv_file.open(
        "r",
        encoding="utf-8-sig",
        newline="",
        errors="replace",
    ) as file:
        reader = csv.DictReader(file)

        if reader.fieldnames is None:
            raise ValueError(f"No CSV header found in {csv_file}")

        for row in reader:
            ip_address = clean_text(row.get("IP"))
            nvt_name = clean_text(row.get("NVT Name"))
            result_id = clean_text(row.get("Result ID"))

            if not ip_address or not nvt_name:
                continue

            records.append(
                {
                    "ip_address": ip_address,
                    "hostname": clean_text(row.get("Hostname")),
                    "port": parse_port(row.get("Port")),
                    "protocol": clean_text(row.get("Port Protocol")),
                    "cvss": parse_cvss(row.get("CVSS")),
                    "severity": clean_text(row.get("Severity")),
                    "solution_type": clean_text(
                        row.get("Solution Type")
                    ),
                    "nvt_name": nvt_name,
                    "summary": clean_text(row.get("Summary")),
                    "specific_result": clean_text(
                        row.get("Specific Result")
                    ),
                    "nvt_oid": clean_text(row.get("NVT OID")),
                    "cves": extract_cves(row.get("CVEs")),
                    "task_id": clean_text(row.get("Task ID")),
                    "task_name": clean_text(row.get("Task Name")),
                    "timestamp": clean_text(row.get("Timestamp")),
                    "result_id": result_id,
                    "impact": clean_text(row.get("Impact")),
                    "solution": clean_text(row.get("Solution")),
                    "affected_software_os": clean_text(
                        row.get("Affected Software/OS")
                    ),
                    "vulnerability_insight": clean_text(
                        row.get("Vulnerability Insight")
                    ),
                    "detection_method": clean_text(
                        row.get("Vulnerability Detection Method")
                    ),
                    "product_detection_result": clean_text(
                        row.get("Product Detection Result")
                    ),
                    "source_file": csv_file.name,
                }
            )

    return records


def deduplicate(records: list[dict]) -> list[dict]:
    unique_records: dict[tuple, dict] = {}

    for record in records:
        result_id = record["result_id"]

        if result_id:
            key = ("result_id", result_id)
        else:
            key = (
                record["ip_address"],
                record["port"],
                record["protocol"],
                record["nvt_oid"],
                record["nvt_name"],
            )

        unique_records[key] = record

    return list(unique_records.values())


def write_vulnerabilities(records: list[dict]) -> Path:
    output_file = OUTPUT_DIR / "vulnerabilities.csv"

    fieldnames = [
        "ip_address",
        "hostname",
        "port",
        "protocol",
        "cvss",
        "severity",
        "solution_type",
        "nvt_name",
        "summary",
        "specific_result",
        "nvt_oid",
        "cves",
        "task_id",
        "task_name",
        "timestamp",
        "result_id",
        "impact",
        "solution",
        "affected_software_os",
        "vulnerability_insight",
        "detection_method",
        "product_detection_result",
        "source_file",
    ]

    with output_file.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    return output_file


def write_summary(records: list[dict]) -> Path:
    output_file = OUTPUT_DIR / "vulnerability_summary.csv"

    counts = Counter(
        (record["ip_address"], record["severity"])
        for record in records
    )

    summary_rows = [
        {
            "ip_address": ip_address,
            "severity": severity or "Unknown",
            "finding_count": count,
        }
        for (ip_address, severity), count in sorted(counts.items())
    ]

    with output_file.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "ip_address",
                "severity",
                "finding_count",
            ],
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    return output_file


def main() -> None:
    csv_files = sorted(RAW_DIR.rglob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No OpenVAS CSV files found under {RAW_DIR}"
        )

    all_records: list[dict] = []

    for csv_file in csv_files:
        records = parse_openvas_file(csv_file)
        all_records.extend(records)

        print(
            f"Parsed {len(records):>4} findings from "
            f"{csv_file.relative_to(RAW_DIR)}"
        )

    records = deduplicate(all_records)

    records.sort(
        key=lambda row: (
            row["ip_address"],
            -float(row["cvss"] or 0),
            int(row["port"] or 0)
            if isinstance(row["port"], int)
            else 0,
        )
    )

    vulnerability_file = write_vulnerabilities(records)
    summary_file = write_summary(records)

    print()
    print(f"Unique findings written: {len(records)}")
    print(f"Output: {vulnerability_file}")
    print(f"Output: {summary_file}")


if __name__ == "__main__":
    main()