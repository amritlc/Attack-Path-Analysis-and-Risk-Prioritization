from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab/risk")

baseline = pd.read_csv(BASE / "cvss_baseline.csv")
pareto = pd.read_csv(BASE / "pareto_prioritization.csv")
comparison = pd.read_csv(BASE / "prioritization_comparison.csv")
ablation = pd.read_csv(BASE / "feature_ablation.csv")


def test_cvss_baseline_tie():
    # The CVSS-only baseline tie is preserved.
    paths = set(
        baseline[baseline["baseline_rank"] == 1]["path_id"]
    )

    assert paths == {"P002", "P003", "P005"}


def test_p002_is_first_front():
    # P002 must be the only first-front path.
    paths = set(
        pareto[pareto["evidence_front"] == 1]["path_id"]
    )

    assert paths == {"P002"}


def test_second_front_paths():
    # P003 and P005 must remain tied.
    paths = set(
        pareto[pareto["evidence_front"] == 2]["path_id"]
    )

    assert paths == {"P003", "P005"}


def test_p004_is_third_front():
    # P004 must remain in the third front.
    paths = set(
        pareto[pareto["evidence_front"] == 3]["path_id"]
    )

    assert paths == {"P004"}


def test_direct_exposure_is_separate():
    # P001 must remain outside vulnerability ranking.
    row = comparison[
        comparison["path_id"] == "P001"
    ].iloc[0]

    assert row["analysis_type"] == "direct_target_exposure"
    assert pd.isna(row["evidence_front"])


def test_p002_ablation_stability():
    # P002 must remain first under each ablation.
    row = ablation[
        ablation["path_id"] == "P002"
    ].iloc[0]

    assert row["full"] == 1
    assert row["without_cvss"] == 1
    assert row["without_epss"] == 1
    assert row["without_kev"] == 1


def test_kev_ablation_effect():
    # KEV removal must remove the P004 distinction.
    values = ablation.set_index("path_id")["without_kev"]

    assert values["P003"] == values["P004"]
    assert values["P004"] == values["P005"]


def test_no_combined_risk_score():
    # No arbitrary combined score must be present.
    assert "risk_score" not in comparison.columns
    assert "weighted_score" not in comparison.columns