from pathlib import Path
import json
import pandas as pd

BASE = Path("data/processed/benchmarks")

DARPA = BASE / "darpa_lldos"
MULVAL = BASE / "mulval_3host"
NOMS = BASE / "noms2022"


def test_darpa_all_phases_present():
    # All benchmark phases must be present.
    stages = pd.read_csv(
        DARPA / "darpa_stage_validation.csv"
    )

    assert set(stages["phase"]) == {
        1, 2, 3, 4, 5
    }


def test_darpa_all_stages_recovered():
    # All documented stages must be recovered.
    stages = pd.read_csv(
        DARPA / "darpa_stage_validation.csv"
    )

    assert stages["recovered"].all()


def test_darpa_order_preserved():
    # Campaign order must be preserved.
    with open(
        DARPA / "darpa_validation_summary.json",
        encoding="utf-8",
    ) as file:
        summary = json.load(file)

    assert summary["order_preserved"] is True
    assert summary["complete_campaign_sequence"] is True


def test_mulval_supported_structure():
    # Comparable MulVAL structure must be recovered.
    with open(
        MULVAL / "mulval_validation_summary.json",
        encoding="utf-8",
    ) as file:
        summary = json.load(file)

    assert summary["passed_checks"] == 7
    assert summary["supported_checks"] == 7
    assert summary[
        "all_supported_structure_recovered"
    ] is True


def test_mulval_unsupported_relations_preserved():
    # Unsupported relations must remain documented.
    relations = pd.read_csv(
        MULVAL / "mulval_unsupported_relations.csv"
    )

    assert len(relations) == 3

    assert set(relations["type"]) == {
        "nfs_export",
        "nfs_mount",
    }


def test_noms_training_leakage_removed():
    # Benchmark CVEs must be removed from training.
    with open(
        NOMS / "noms_ai_summary.json",
        encoding="utf-8",
    ) as file:
        summary = json.load(file)

    assert summary["original_training_rows"] == 1344
    assert summary["benchmark_training_rows"] == 1342
    assert summary["held_out_cves"] == 2


def test_noms_no_exact_description_duplicates():
    # Exact description duplicates must be absent.
    with open(
        NOMS / "noms_ai_summary.json",
        encoding="utf-8",
    ) as file:
        summary = json.load(file)

    assert summary[
        "exact_description_duplicates"
    ] == 0


def test_noms_reference_mappings_recovered():
    # Published NOMS mappings must be checked.
    validation = pd.read_csv(
        NOMS / "noms_ai_validation.csv"
    )

    assert len(validation) == 2
    assert validation["recovered"].all()


def test_noms_expected_cves_present():
    # Both reference CVEs must be represented.
    validation = pd.read_csv(
        NOMS / "noms_ai_validation.csv"
    )

    assert set(validation["cve_id"]) == {
        "CVE-2017-0262",
        "CVE-2017-0263",
    }


def test_all_benchmarks_pass():
    # Each validation dimension must pass.
    summary = pd.read_csv(
        BASE / "benchmark_summary.csv"
    )

    assert set(summary["benchmark"]) == {
        "DARPA LLDOS 1.0",
        "MulVAL 3-host",
        "NOMS 2022",
    }

    assert summary["passed"].all()