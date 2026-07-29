from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MANUAL_DIR = PROJECT_ROOT / "data" / "manual"


def load_csv(
    file_path: Path,
    required_columns: set[str] | None = None,
) -> list[dict[str, str]]:
    """
    Load a CSV file and optionally validate its required columns.
    """

    if not file_path.exists():
        raise FileNotFoundError(
            f"CSV file not found: {file_path}"
        )

    with file_path.open(
        mode="r",
        encoding="utf-8-sig",
        newline="",
        errors="replace",
    ) as file:
        reader = csv.DictReader(file)

        if reader.fieldnames is None:
            raise ValueError(
                f"No CSV header found in: {file_path}"
            )

        available_columns = set(reader.fieldnames)

        if required_columns:
            missing_columns = (
                required_columns - available_columns
            )

            if missing_columns:
                raise ValueError(
                    f"{file_path.name} is missing columns: "
                    f"{sorted(missing_columns)}"
                )

        return [
            {
                key: clean(value)
                for key, value in row.items()
            }
            for row in reader
        ]


def clean(value: Any) -> str:
    """Convert a value to clean text."""

    if value is None:
        return ""

    return " ".join(str(value).split())


def load_hosts() -> list[dict[str, str]]:
    return load_csv(
        PROCESSED_DIR / "hosts.csv",
        required_columns={
            "ip_address",
            "status",
        },
    )


def load_services() -> list[dict[str, str]]:
    return load_csv(
        PROCESSED_DIR / "services.csv",
        required_columns={
            "ip_address",
            "protocol",
            "port",
            "service_name",
        },
    )


def load_enriched_vulnerabilities() -> list[dict[str, str]]:
    return load_csv(
        PROCESSED_DIR
        / "enriched_vulnerability_findings.csv",
        required_columns={
            "ip_address",
            "port",
            "protocol",
            "nvt_name",
            "cvss",
        },
    )


def load_assets() -> list[dict[str, str]]:
    return load_csv(
        MANUAL_DIR / "assets.csv",
        required_columns={
            "asset_id",
            "ip_address",
            "hostname",
            "criticality_score",
        },
    )


def load_network_connections() -> list[dict[str, str]]:
    return load_csv(
        MANUAL_DIR / "network_connections.csv",
        required_columns={
            "source",
            "target",
            "protocol",
            "port",
            "connection_type",
        },
    )

def load_access_conditions() -> list[dict[str, str]]:
    return load_csv(
        MANUAL_DIR / "access_conditions.csv",
        required_columns={
            "condition_id",
            "source_asset",
            "target_asset",
            "protocol",
            "port",
            "condition_type",
            "evidence_type",
            "confidence",
            "description",
        },
    )    