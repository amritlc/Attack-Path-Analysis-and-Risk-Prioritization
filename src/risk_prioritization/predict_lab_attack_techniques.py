from pathlib import Path
import json
import joblib
import pandas as pd

LAB = Path("data/processed/lab/enrichment/nvd_enrichment.csv")
DATA = Path("data/processed/cve2attack")
MODEL = Path("models/cve2attack")
OUT = Path("data/processed/lab/risk")

OUT.mkdir(parents=True, exist_ok=True)

# Lab CVEs and real NVD descriptions are loaded.
lab = pd.read_csv(LAB)

lab = lab[
    ["cve_id", "nvd_description"]
].drop_duplicates("cve_id")

lab = lab[
    lab["nvd_description"].notna()
].reset_index(drop=True)

# Model training and test CVEs are loaded for provenance.
train = pd.read_csv(
    DATA / "X_train_clean.csv"
)

test = pd.read_csv(
    DATA / "X_test.csv"
)

train_cves = set(train["Name"])
test_cves = set(test["Name"])

# The trained model and selected threshold are loaded.
vectorizer = joblib.load(
    MODEL / "tfidf_vectorizer_tuned.joblib"
)

classifier = joblib.load(
    MODEL / "attack_classifier_tuned.joblib"
)

with open(
    MODEL / "threshold.json",
    encoding="utf-8",
) as file:
    threshold = json.load(file)["threshold"]

# ATT&CK technique labels are loaded.
labels = list(
    pd.read_csv(
        DATA / "y_train_clean.csv"
    ).columns
)

# CVE descriptions are transformed.
vectors = vectorizer.transform(
    lab["nvd_description"]
)

# Technique probabilities are generated.
probabilities = classifier.predict_proba(
    vectors
)

prediction_rows = []
summary_rows = []

for index, row in lab.iterrows():
    cve = row["cve_id"]

    # Dataset provenance is recorded.
    if cve in train_cves:
        provenance = "train_seen"
    elif cve in test_cves:
        provenance = "test_seen"
    else:
        provenance = "unseen"

    predictions = []

    # Predictions meeting the validation-selected threshold are retained.
    for label_index, label in enumerate(labels):
        probability = float(
            probabilities[index][label_index]
        )

        if probability >= threshold:
            predictions.append(
                (label, probability)
            )

    predictions.sort(
        key=lambda item: item[1],
        reverse=True,
    )

    # Long-form prediction rows are created.
    for label, probability in predictions:
        prediction_rows.append({
            "cve_id": cve,
            "provenance": provenance,
            "attack_technique": label,
            "model_probability": round(
                probability,
                6,
            ),
            "threshold": round(
                threshold,
                6,
            ),
        })

    # One summary row is created for every lab CVE.
    summary_rows.append({
        "cve_id": cve,
        "provenance": provenance,
        "prediction_count": len(predictions),
        "top_attack_technique": (
            predictions[0][0]
            if predictions
            else pd.NA
        ),
        "top_probability": (
            round(predictions[0][1], 6)
            if predictions
            else pd.NA
        ),
        "threshold": round(
            threshold,
            6,
        ),
    })

predictions = pd.DataFrame(
    prediction_rows
)

summary = pd.DataFrame(
    summary_rows
)

predictions.to_csv(
    OUT / "lab_attack_predictions.csv",
    index=False,
)

summary.to_csv(
    OUT / "lab_attack_prediction_summary.csv",
    index=False,
)

# Prediction coverage is calculated.
with_predictions = (
    summary["prediction_count"] > 0
).sum()

train_seen = (
    summary["provenance"] == "train_seen"
).sum()

test_seen = (
    summary["provenance"] == "test_seen"
).sum()

unseen = (
    summary["provenance"] == "unseen"
).sum()

print(f"Lab CVEs analysed: {len(summary)}")
print(f"Train-seen CVEs: {train_seen}")
print(f"Test-seen CVEs: {test_seen}")
print(f"Unseen CVEs: {unseen}")
print(f"CVEs with predictions: {with_predictions}")
print(
    "Predicted CVE-technique links:",
    len(predictions),
)

print()
print("Prediction summary:")
print(
    summary.head(20).to_string(
        index=False
    )
)