from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

VULNERABILITIES_FILE = PROCESSED_DIR / "vulnerabilities.csv"
ENRICHMENT_FILE = PROCESSED_DIR / "cve_enrichment.csv"

OUTPUT_FILE = PROCESSED_DIR / "enriched_vulnerability_findings.csv"
SUMMARY_FILE = PROCESSED_DIR / "enrichment_merge_summary.csv"

CVE_PATTERN = re.compile(
    r"CVE-\d{4}-\d{4,7}",
    re.IGNORECASE,
)


def clean(value: Any) -> str:
    if value is None:
        return ""

    return " ".join(str(value).split())


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
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


def extract_cves(value: Any) -> list[str]:
    return sorted(
        {
            match.upper()
            for match in CVE_PATTERN.findall(clean(value))
        }
    )


def port_sort_value(value: Any) -> int:
    try:
        return int(float(clean(value)))
    except ValueError:
        return 0


def main() -> None:
    vulnerabilities = read_csv(VULNERABILITIES_FILE)
    enrichment_rows = read_csv(ENRICHMENT_FILE)

    enrichment_by_cve = {
        clean(row.get("cve_id")).upper(): row
        for row in enrichment_rows
        if clean(row.get("cve_id"))
    }

    output_rows: list[dict[str, Any]] = []

    findings_with_cve = 0
    findings_without_cve = 0
    matched_cve_links = 0
    unmatched_cve_links = 0

    for finding in vulnerabilities:
        cve_ids = extract_cves(finding.get("cves"))

        if not cve_ids:
            findings_without_cve += 1

            output_row = dict(finding)
            output_row["cve_id"] = ""
            output_row["cve_enrichment_status"] = "no_cve"

            output_rows.append(output_row)
            continue

        findings_with_cve += 1

        # One OpenVAS finding may reference several CVEs.
        # Create one output row per finding-CVE relationship.
        for cve_id in cve_ids:
            output_row = dict(finding)
            output_row["cve_id"] = cve_id

            enrichment = enrichment_by_cve.get(cve_id)

            if enrichment:
                output_row["cve_enrichment_status"] = "matched"

                for key, value in enrichment.items():
                    if key != "cve_id":
                        output_row[key] = value

                matched_cve_links += 1

            else:
                output_row["cve_enrichment_status"] = "missing"
                unmatched_cve_links += 1

            output_rows.append(output_row)

    output_rows.sort(
        key=lambda row: (
            clean(row.get("ip_address")),
            port_sort_value(row.get("port")),
            clean(row.get("cve_id")),
            clean(row.get("nvt_name")),
        )
    )

    vulnerability_fields = (
        list(vulnerabilities[0].keys())
        if vulnerabilities
        else []
    )

    enrichment_fields = (
        [
            field
            for field in enrichment_rows[0].keys()
            if field != "cve_id"
            and field not in vulnerability_fields
        ]
        if enrichment_rows
        else []
    )

    output_fields = (
        vulnerability_fields
        + [
            "cve_id",
            "cve_enrichment_status",
        ]
        + enrichment_fields
    )

    write_csv(
        OUTPUT_FILE,
        output_rows,
        output_fields,
    )

    summary_rows = [
        {
            "metric": "original_openvas_findings",
            "value": len(vulnerabilities),
        },
        {
            "metric": "findings_with_cve",
            "value": findings_with_cve,
        },
        {
            "metric": "findings_without_cve",
            "value": findings_without_cve,
        },
        {
            "metric": "matched_finding_cve_links",
            "value": matched_cve_links,
        },
        {
            "metric": "unmatched_finding_cve_links",
            "value": unmatched_cve_links,
        },
        {
            "metric": "enriched_output_rows",
            "value": len(output_rows),
        },
    ]

    write_csv(
        SUMMARY_FILE,
        summary_rows,
        ["metric", "value"],
    )

    print(f"OpenVAS findings loaded: {len(vulnerabilities)}")
    print(f"CVEs available for enrichment: {len(enrichment_by_cve)}")
    print(f"Matched finding-CVE links: {matched_cve_links}")
    print(f"Unmatched finding-CVE links: {unmatched_cve_links}")
    print(f"Output rows written: {len(output_rows)}")
    print(f"Output: {OUTPUT_FILE}")
    print(f"Output: {SUMMARY_FILE}")


if __name__ == "__main__":
    main()