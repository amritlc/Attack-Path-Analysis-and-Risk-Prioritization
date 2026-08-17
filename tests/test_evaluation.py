from pathlib import Path

import pandas as pd
import pytest


BASE = Path("data/processed/lab/evaluation")
FIGURES = Path("images/evaluation")


def test_host_vs_graph_results():
    data = pd.read_csv(
        BASE / "host_graph_metrics.csv"
    ).iloc[0]

    assert data["host_count"] == 4
    assert data["path_count"] == 5
    assert data["multi_stage_path_count"] == 4
    assert data["candidate_compromise_steps"] == 6
    assert data["unique_compromise_transitions"] == 4


def test_cvss_vs_pareto_results():
    data = pd.read_csv(
        BASE / "cvss_pareto_summary.csv"
    ).iloc[0]

    assert data["cvss_top_group_size"] == 3
    assert data["pareto_front1_size"] == 1
    assert data["top_group_reduction"] == 2


def test_ablation_results():
    data = pd.read_csv(
        BASE / "ablation_summary.csv"
    )

    changes = dict(
        zip(
            data["removed_evidence"],
            data["changed_path_count"],
        )
    )

    assert changes["CVSS"] == 0
    assert changes["EPSS"] == 0
    assert changes["KEV"] == 1


def test_ai_model_results():
    data = pd.read_csv(
        BASE / "ai_model_comparison.csv"
    )

    baseline = data.iloc[0]
    tuned = data.iloc[1]

    assert baseline["micro_f1"] == pytest.approx(
        0.1447963801
    )

    assert tuned["micro_f1"] == pytest.approx(
        0.4568200161
    )

    assert tuned["micro_f1"] > baseline["micro_f1"]


def test_ai_prediction_coverage():
    data = pd.read_csv(
        BASE / "ai_lab_coverage.csv"
    ).iloc[0]

    assert data["lab_cve_count"] == 77
    assert data["cves_with_predictions"] == 72
    assert data["cves_without_predictions"] == 5

    assert data[
        "lab_prediction_coverage"
    ] == pytest.approx(
        72 / 77
    )


def test_public_benchmarks():
    data = pd.read_csv(
        BASE / "public_benchmark_evaluation.csv"
    )

    assert len(data) == 3

    recovered = dict(
        zip(
            data["benchmark"],
            data["recovered_items"],
        )
    )

    assert recovered["DARPA LLDOS 1.0"] == 5
    assert recovered["MulVAL 3-host"] == 7
    assert recovered["NOMS 2022"] == 2


def test_pipeline_runtime():
    data = pd.read_csv(
        BASE / "pipeline_runtime_summary.csv"
    ).iloc[0]

    assert data["runs"] == 5
    assert data["min_seconds"] > 0

    assert (
        data["min_seconds"]
        <= data["median_seconds"]
        <= data["max_seconds"]
    )


def test_scalability_results():
    data = pd.read_csv(
        BASE / "scalability_summary.csv"
    )

    assert len(data) == 5

    largest = data.sort_values(
        "host_count"
    ).iloc[-1]

    assert largest["host_count"] == 80
    assert largest["vulnerability_count"] == 6240
    assert largest["graph_nodes"] == 6398
    assert largest["graph_edges"] == 12558
    assert largest["path_count"] == 3081

    assert largest["median_seconds"] > 0
    assert largest["mean_peak_memory_mb"] > 0


def test_evaluation_figures_exist():
    expected = [
        "experimental_network_architecture.png",
        "attack_path_overview.png",
        "ablation_effect.png",
        "ai_path_coverage.png",
        "cvss_vs_pareto.png",
        "ai_model_comparison.png",
        "runtime_by_stage.png",
        "scalability_runtime.png",
        "scalability_memory.png",
    ]

    for name in expected:
        path = FIGURES / name

        assert path.exists()
        assert path.stat().st_size > 0


def test_highest_priority_figure_exists():
    path = Path(
        "images/highest_priority_attack_path.png"
    )

    assert path.exists()
    assert path.stat().st_size > 0