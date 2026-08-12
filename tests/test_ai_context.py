from pathlib import Path
import json
import pandas as pd

RISK = Path("data/processed/lab/risk")
MODEL = Path("models/cve2attack")

predictions = pd.read_csv(
    RISK / "lab_attack_predictions.csv"
)

cve_summary = pd.read_csv(
    RISK / "lab_attack_prediction_summary.csv"
)

path_summary = pd.read_csv(
    RISK / "path_attack_context_summary.csv"
)

with open(
    MODEL / "threshold.json",
    encoding="utf-8",
) as file:
    threshold = json.load(file)["threshold"]

with open(
    MODEL / "metrics.json",
    encoding="utf-8",
) as file:
    baseline_metrics = json.load(file)

with open(
    MODEL / "tuned_metrics.json",
    encoding="utf-8",
) as file:
    tuned_metrics = json.load(file)


def test_all_lab_cves_analysed():
    # All lab CVEs must be analysed.
    assert len(cve_summary) == 77


def test_prediction_provenance():
    # Model-dataset provenance must be preserved.
    assert (cve_summary["provenance"] == "train_seen").sum() == 4
    assert (cve_summary["provenance"] == "test_seen").sum() == 0
    assert (cve_summary["provenance"] == "unseen").sum() == 73


def test_threshold_is_valid():
    # The selected threshold must be a valid probability.
    assert 0 < threshold < 1


def test_predictions_meet_threshold():
    # Stored predictions must meet the selected threshold.
    stored_threshold = round(threshold, 6)

    assert (
        predictions["model_probability"]
        >= stored_threshold
    ).all()


def test_probabilities_are_valid():
    # Model probabilities must remain between zero and one.
    assert (
        predictions["model_probability"]
        .between(0, 1)
        .all()
    )


def test_threshold_tuning_improves_micro_f1():
    # Tuned Micro-F1 must exceed the default baseline.
    assert (
        tuned_metrics["micro_f1"]
        > baseline_metrics["micro_f1"]
    )


def test_all_attack_paths_have_context_summary():
    # Every generated path must be represented.
    assert set(path_summary["path_id"]) == {
        "P001",
        "P002",
        "P003",
        "P004",
        "P005",
    }


def test_path_prediction_coverage():
    # Coverage must match observed and predicted CVE counts.
    for _, row in path_summary.iterrows():
        observed = row["observed_cve_count"]
        predicted = row["predicted_cve_count"]

        assert predicted <= observed

        if observed == 0:
            continue

        expected = round(
            predicted / observed,
            4,
        )

        assert row["prediction_coverage"] == expected


def test_p001_has_no_ai_vulnerability_context():
    # Direct target exposure must not receive invented AI context.
    row = path_summary[
        path_summary["path_id"] == "P001"
    ].iloc[0]

    assert row["observed_cve_count"] == 0
    assert row["predicted_cve_count"] == 0
    assert row["predicted_technique_count"] == 0


def test_no_ai_risk_score():
    # ATT&CK predictions must not create an artificial risk score.
    forbidden = {
        "ai_risk_score",
        "risk_score",
        "weighted_score",
    }

    assert forbidden.isdisjoint(predictions.columns)
    assert forbidden.isdisjoint(path_summary.columns)