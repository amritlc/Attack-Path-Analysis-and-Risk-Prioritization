from __future__ import annotations

import csv
import json
import os
import time
from pathlib import Path
from typing import Any

import requests


PROJECT_ROOT = Path(__file__).resolve().parents[1]

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
RAW_EXTERNAL_DIR = PROJECT_ROOT / "data" / "raw" / "external"
NVD_CACHE_DIR = RAW_EXTERNAL_DIR / "nvd"

INPUT_FILE = PROCESSED_DIR / "unique_cves.csv"
OUTPUT_FILE = PROCESSED_DIR / "cve_enrichment.csv"
SUMMARY_FILE = PROCESSED_DIR / "cve_enrichment_summary.csv"

EPSS_API = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

RAW_EXTERNAL_DIR.mkdir(parents=True, exist_ok=True)
NVD_CACHE_DIR.mkdir(parents=True, exist_ok=True)

SESSION = requests.Session()
SESSION.headers.update(
    {
        "User-Agent": (
            "MSc-Attack-Path-Analysis-Research/1.0"
        )
    }
)


def clean(value: Any) -> str:
    if value is None:
        return ""

    return " ".join(str(value).split())


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


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_json(path: Path, data: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def fetch_json(
    url: str,
    *,
    cache_file: Path,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    retries: int = 4,
) -> tuple[dict[str, Any], bool]:
    """
    Return JSON and whether it came from the local cache.
    """

    if cache_file.exists():
        return load_json(cache_file), True

    for attempt in range(1, retries + 1):
        try:
            response = SESSION.get(
                url,
                params=params,
                headers=headers,
                timeout=60,
            )

            if response.status_code == 429:
                wait_time = int(
                    response.headers.get(
                        "Retry-After",
                        str(2 ** attempt),
                    )
                )
                print(
                    f"Rate limited. Waiting {wait_time} seconds..."
                )
                time.sleep(wait_time)
                continue

            response.raise_for_status()

            data = response.json()
            save_json(cache_file, data)

            return data, False

        except (
            requests.RequestException,
            ValueError,
        ) as error:
            if attempt == retries:
                raise RuntimeError(
                    f"Request failed for {url}: {error}"
                ) from error

            wait_time = 2 ** attempt
            print(
                f"Request error. Retrying in {wait_time} seconds..."
            )
            time.sleep(wait_time)

    raise RuntimeError(f"Unable to retrieve {url}")


def create_epss_batches(
    cve_ids: list[str],
    maximum_characters: int = 1800,
) -> list[list[str]]:
    """
    Keep the comma-separated CVE parameter below the API limit.
    """

    batches: list[list[str]] = []
    current_batch: list[str] = []
    current_length = 0

    for cve_id in cve_ids:
        added_length = len(cve_id)

        if current_batch:
            added_length += 1

        if (
            current_batch
            and current_length + added_length
            > maximum_characters
        ):
            batches.append(current_batch)
            current_batch = [cve_id]
            current_length = len(cve_id)
        else:
            current_batch.append(cve_id)
            current_length += added_length

    if current_batch:
        batches.append(current_batch)

    return batches


def get_epss_data(
    cve_ids: list[str],
) -> dict[str, dict[str, str]]:
    epss_by_cve: dict[str, dict[str, str]] = {}

    batches = create_epss_batches(cve_ids)

    for index, batch in enumerate(batches, start=1):
        cache_file = (
            RAW_EXTERNAL_DIR / f"epss_batch_{index}.json"
        )

        data, _ = fetch_json(
            EPSS_API,
            cache_file=cache_file,
            params={"cve": ",".join(batch)},
        )

        for item in data.get("data", []):
            cve_id = clean(item.get("cve")).upper()

            if not cve_id:
                continue

            epss_by_cve[cve_id] = {
                "epss": clean(item.get("epss")),
                "epss_percentile": clean(
                    item.get("percentile")
                ),
                "epss_date": clean(item.get("date")),
            }

    return epss_by_cve


def get_kev_data() -> dict[str, dict[str, str]]:
    cache_file = RAW_EXTERNAL_DIR / "cisa_kev.json"

    data, _ = fetch_json(
        CISA_KEV_URL,
        cache_file=cache_file,
    )

    kev_by_cve: dict[str, dict[str, str]] = {}

    for item in data.get("vulnerabilities", []):
        cve_id = clean(item.get("cveID")).upper()

        if not cve_id:
            continue

        cwes = item.get("cwes", [])

        kev_by_cve[cve_id] = {
            "kev": "yes",
            "kev_vendor_project": clean(
                item.get("vendorProject")
            ),
            "kev_product": clean(item.get("product")),
            "kev_vulnerability_name": clean(
                item.get("vulnerabilityName")
            ),
            "kev_date_added": clean(item.get("dateAdded")),
            "kev_due_date": clean(item.get("dueDate")),
            "kev_required_action": clean(
                item.get("requiredAction")
            ),
            "kev_known_ransomware_use": clean(
                item.get("knownRansomwareCampaignUse")
            ),
            "kev_cwes": ";".join(cwes)
            if isinstance(cwes, list)
            else "",
        }

    return kev_by_cve


def select_english_description(
    descriptions: list[dict[str, Any]],
) -> str:
    for description in descriptions:
        if description.get("lang") == "en":
            return clean(description.get("value"))

    return ""


def extract_cwes(cve_record: dict[str, Any]) -> str:
    cwes: set[str] = set()

    for weakness in cve_record.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = clean(description.get("value"))

            if value.upper().startswith("CWE-"):
                cwes.add(value.upper())

    return ";".join(sorted(cwes))


def choose_cvss_metric(
    metrics: dict[str, Any],
) -> dict[str, str]:
    metric_order = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]

    for metric_name in metric_order:
        candidates = metrics.get(metric_name, [])

        if not candidates:
            continue

        selected = next(
            (
                candidate
                for candidate in candidates
                if candidate.get("type") == "Primary"
            ),
            candidates[0],
        )

        cvss_data = selected.get("cvssData", {})

        return {
            "nvd_cvss_version": clean(
                cvss_data.get("version")
            ),
            "nvd_base_score": clean(
                cvss_data.get("baseScore")
            ),
            "nvd_base_severity": clean(
                cvss_data.get("baseSeverity")
                or selected.get("baseSeverity")
            ),
            "nvd_vector": clean(
                cvss_data.get("vectorString")
            ),
            "nvd_metric_source": clean(
                selected.get("source")
            ),
        }

    return {
        "nvd_cvss_version": "",
        "nvd_base_score": "",
        "nvd_base_severity": "",
        "nvd_vector": "",
        "nvd_metric_source": "",
    }


def parse_nvd_response(
    data: dict[str, Any],
) -> dict[str, str]:
    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        return {
            "nvd_found": "no",
            "nvd_status": "not_found",
        }

    cve_record = vulnerabilities[0].get("cve", {})

    result = {
        "nvd_found": "yes",
        "nvd_status": clean(cve_record.get("vulnStatus")),
        "nvd_source_identifier": clean(
            cve_record.get("sourceIdentifier")
        ),
        "nvd_published": clean(cve_record.get("published")),
        "nvd_last_modified": clean(
            cve_record.get("lastModified")
        ),
        "nvd_description": select_english_description(
            cve_record.get("descriptions", [])
        ),
        "nvd_cwes": extract_cwes(cve_record),
    }

    result.update(
        choose_cvss_metric(cve_record.get("metrics", {}))
    )

    return result


def get_nvd_data(
    cve_ids: list[str],
) -> dict[str, dict[str, str]]:
    nvd_by_cve: dict[str, dict[str, str]] = {}

    api_key = os.getenv("NVD_API_KEY", "").strip()

    headers = {"apiKey": api_key} if api_key else None

    # Public requests must be considerably slower.
    delay_seconds = 1.0 if api_key else 6.5

    total = len(cve_ids)

    for index, cve_id in enumerate(cve_ids, start=1):
        print(f"NVD {index}/{total}: {cve_id}")

        cache_file = NVD_CACHE_DIR / f"{cve_id}.json"

        try:
            data, from_cache = fetch_json(
                NVD_API,
                cache_file=cache_file,
                params={"cveId": cve_id},
                headers=headers,
            )

            nvd_by_cve[cve_id] = parse_nvd_response(data)

            if not from_cache and index < total:
                time.sleep(delay_seconds)

        except RuntimeError as error:
            print(f"Warning: {error}")

            nvd_by_cve[cve_id] = {
                "nvd_found": "error",
                "nvd_status": "request_error",
            }

    return nvd_by_cve


def main() -> None:
    input_rows = read_csv(INPUT_FILE)

    cve_ids = sorted(
        {
            clean(row.get("cve_id")).upper()
            for row in input_rows
            if clean(row.get("cve_id"))
        }
    )

    print(f"Unique CVEs loaded: {len(cve_ids)}")
    print("Retrieving EPSS data...")
    epss_by_cve = get_epss_data(cve_ids)

    print("Retrieving CISA KEV data...")
    kev_by_cve = get_kev_data()

    print("Retrieving NVD data...")
    nvd_by_cve = get_nvd_data(cve_ids)

    output_rows: list[dict[str, Any]] = []

    enrichment_fields = [
        "epss",
        "epss_percentile",
        "epss_date",
        "kev",
        "kev_vendor_project",
        "kev_product",
        "kev_vulnerability_name",
        "kev_date_added",
        "kev_due_date",
        "kev_required_action",
        "kev_known_ransomware_use",
        "kev_cwes",
        "nvd_found",
        "nvd_status",
        "nvd_source_identifier",
        "nvd_published",
        "nvd_last_modified",
        "nvd_description",
        "nvd_cwes",
        "nvd_cvss_version",
        "nvd_base_score",
        "nvd_base_severity",
        "nvd_vector",
        "nvd_metric_source",
    ]

    for row in input_rows:
        cve_id = clean(row.get("cve_id")).upper()

        combined = dict(row)

        combined.update(
            {
                "epss": "",
                "epss_percentile": "",
                "epss_date": "",
                "kev": "no",
                "kev_vendor_project": "",
                "kev_product": "",
                "kev_vulnerability_name": "",
                "kev_date_added": "",
                "kev_due_date": "",
                "kev_required_action": "",
                "kev_known_ransomware_use": "",
                "kev_cwes": "",
                "nvd_found": "",
                "nvd_status": "",
                "nvd_source_identifier": "",
                "nvd_published": "",
                "nvd_last_modified": "",
                "nvd_description": "",
                "nvd_cwes": "",
                "nvd_cvss_version": "",
                "nvd_base_score": "",
                "nvd_base_severity": "",
                "nvd_vector": "",
                "nvd_metric_source": "",
            }
        )

        combined.update(epss_by_cve.get(cve_id, {}))
        combined.update(kev_by_cve.get(cve_id, {}))
        combined.update(nvd_by_cve.get(cve_id, {}))

        output_rows.append(combined)

    fieldnames = list(input_rows[0].keys()) + enrichment_fields

    write_csv(
        OUTPUT_FILE,
        output_rows,
        fieldnames,
    )

    summary_rows = [
        {
            "metric": "unique_cves",
            "value": len(output_rows),
        },
        {
            "metric": "cves_with_epss",
            "value": sum(
                bool(row.get("epss"))
                for row in output_rows
            ),
        },
        {
            "metric": "cves_in_cisa_kev",
            "value": sum(
                row.get("kev") == "yes"
                for row in output_rows
            ),
        },
        {
            "metric": "cves_found_in_nvd",
            "value": sum(
                row.get("nvd_found") == "yes"
                for row in output_rows
            ),
        },
        {
            "metric": "cves_without_nvd_cvss",
            "value": sum(
                not row.get("nvd_base_score")
                for row in output_rows
            ),
        },
    ]

    write_csv(
        SUMMARY_FILE,
        summary_rows,
        ["metric", "value"],
    )

    print()
    print(f"Enriched CVEs written: {len(output_rows)}")
    print(f"Output: {OUTPUT_FILE}")
    print(f"Output: {SUMMARY_FILE}")


if __name__ == "__main__":
    main()