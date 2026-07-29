from __future__ import annotations

import csv
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

INPUT_FILE = PROCESSED_DIR / "vulnerabilities.csv"
CVE_OUTPUT_FILE = PROCESSED_DIR / "unique_cves.csv"
NO_CVE_OUTPUT_FILE = PROCESSED_DIR / "findings_without_cve.csv"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def clean(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split())


def safe_float(value: Any) -> float:
    try:
        return float(clean(value))
    except ValueError:
        return 0.0


def extract_cve_ids(value: Any) -> list[str]:
    return sorted(
        {
            match.upper()
            for match in CVE_PATTERN.findall(clean(value))
        }
    )


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
        errors="replace",
    ) as file:
        return list(csv.DictReader(file))


def write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    fieldnames: list[str],
) -> None:
    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    findings = read_csv(INPUT_FILE)

    cve_data: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "finding_count": 0,
            "hosts": set(),
            "ports": set(),
            "protocols": set(),
            "severities": set(),
            "nvt_names": set(),
            "max_cvss": 0.0,
        }
    )

    findings_without_cve: list[dict[str, str]] = []

    for finding in findings:
        cve_ids = extract_cve_ids(finding.get("cves"))

        if not cve_ids:
            findings_without_cve.append(finding)
            continue

        for cve_id in cve_ids:
            record = cve_data[cve_id]

            record["finding_count"] += 1
            record["hosts"].add(clean(finding.get("ip_address")))
            record["ports"].add(clean(finding.get("port")))
            record["protocols"].add(clean(finding.get("protocol")))
            record["severities"].add(clean(finding.get("severity")))
            record["nvt_names"].add(clean(finding.get("nvt_name")))

            record["max_cvss"] = max(
                record["max_cvss"],
                safe_float(finding.get("cvss")),
            )

    cve_rows: list[dict[str, Any]] = []

    for cve_id, record in sorted(cve_data.items()):
        cve_rows.append(
            {
                "cve_id": cve_id,
                "finding_count": record["finding_count"],
                "host_count": len(record["hosts"]),
                "hosts": ";".join(sorted(filter(None, record["hosts"]))),
                "ports": ";".join(sorted(filter(None, record["ports"]))),
                "protocols": ";".join(
                    sorted(filter(None, record["protocols"]))
                ),
                "max_openvas_cvss": record["max_cvss"],
                "severities": ";".join(
                    sorted(filter(None, record["severities"]))
                ),
                "nvt_names": ";".join(
                    sorted(filter(None, record["nvt_names"]))
                ),
            }
        )

    cve_fieldnames = [
        "cve_id",
        "finding_count",
        "host_count",
        "hosts",
        "ports",
        "protocols",
        "max_openvas_cvss",
        "severities",
        "nvt_names",
    ]

    no_cve_fieldnames = list(findings[0].keys()) if findings else []

    write_csv(
        CVE_OUTPUT_FILE,
        cve_rows,
        cve_fieldnames,
    )

    if no_cve_fieldnames:
        write_csv(
            NO_CVE_OUTPUT_FILE,
            findings_without_cve,
            no_cve_fieldnames,
        )

    print(f"OpenVAS findings loaded: {len(findings)}")
    print(f"Unique CVEs extracted: {len(cve_rows)}")
    print(f"Findings without CVEs: {len(findings_without_cve)}")
    print(f"Output: {CVE_OUTPUT_FILE}")
    print(f"Output: {NO_CVE_OUTPUT_FILE}")


if __name__ == "__main__":
    main()