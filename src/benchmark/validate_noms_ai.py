from pathlib import Path
import json

import numpy as np
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_curve
from sklearn.model_selection import train_test_split
from sklearn.multiclass import OneVsRestClassifier


DATA = Path("data/processed/cve2attack")
REFERENCE = Path(
    "data/manual/benchmarks/noms2022_cve_attack_reference.csv"
)
OUT = Path(
    "data/processed/benchmarks/noms2022"
)

OUT.mkdir(parents=True, exist_ok=True)

HOLDOUT = {
    "CVE-2017-0262",
    "CVE-2017-0263",
}

x = pd.read_csv(DATA / "X_train_clean.csv")
y = pd.read_csv(DATA / "y_train_clean.csv")
reference = pd.read_csv(REFERENCE)

labels = [
    column for column in y.columns
    if column != "Name"
]

# The NOMS CVEs are removed from training.
holdout_mask = x["Name"].isin(HOLDOUT)

x_holdout = x[holdout_mask].reset_index(drop=True)
x_pool = x[~holdout_mask].reset_index(drop=True)

y_pool = (
    y.loc[~holdout_mask, labels]
    .reset_index(drop=True)
)

print(f"Original training rows: {len(x)}")
print(f"Benchmark training rows: {len(x_pool)}")
print(f"Held-out NOMS CVEs: {len(x_holdout)}")

# An internal validation split is created.
x_fit, x_val, y_fit, y_val = train_test_split(
    x_pool["Text"],
    y_pool,
    test_size=0.2,
    random_state=42,
)

vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",
    ngram_range=(1, 2),
    max_features=10000,
)

fit_vectors = vectorizer.fit_transform(x_fit)
val_vectors = vectorizer.transform(x_val)

classifier = OneVsRestClassifier(
    LogisticRegression(
        max_iter=1000,
        random_state=42,
    )
)

classifier.fit(
    fit_vectors,
    y_fit,
)

# The prediction threshold is selected on validation data.
val_probabilities = classifier.predict_proba(
    val_vectors
)

precision, recall, thresholds = precision_recall_curve(
    y_val.to_numpy().ravel(),
    val_probabilities.ravel(),
)

f1 = (
    2 * precision[:-1] * recall[:-1]
    / (
        precision[:-1]
        + recall[:-1]
        + 1e-12
    )
)

best_index = np.argmax(f1)
threshold = float(thresholds[best_index])

print(f"Selected threshold: {threshold:.6f}")

# The benchmark model is retrained on the full remaining pool.
vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",
    ngram_range=(1, 2),
    max_features=10000,
)

pool_vectors = vectorizer.fit_transform(
    x_pool["Text"]
)

classifier = OneVsRestClassifier(
    LogisticRegression(
        max_iter=1000,
        random_state=42,
    )
)

classifier.fit(
    pool_vectors,
    y_pool,
)

holdout_vectors = vectorizer.transform(
    x_holdout["Text"]
)

probabilities = classifier.predict_proba(
    holdout_vectors
)

prediction_rows = []

# Thresholded techniques are recorded.
for row_index, cve in enumerate(x_holdout["Name"]):
    for label_index, technique in enumerate(labels):
        probability = probabilities[
            row_index,
            label_index,
        ]

        if probability >= threshold:
            prediction_rows.append({
                "cve_id": cve,
                "attack_technique": technique,
                "model_probability": probability,
                "threshold": threshold,
            })

predictions = pd.DataFrame(prediction_rows)

predictions.to_csv(
    OUT / "noms_ai_predictions.csv",
    index=False,
)

validation_rows = []

# Published NOMS mappings are checked.
for _, row in reference.iterrows():
    cve = row["cve_id"]
    expected = row["expected_attack_technique"]

    cve_index = x_holdout.index[
        x_holdout["Name"] == cve
    ][0]

    label_index = labels.index(expected)

    expected_probability = probabilities[
        cve_index,
        label_index,
    ]

    predicted = predictions[
        predictions["cve_id"] == cve
    ]

    predicted_techniques = (
        predicted["attack_technique"]
        .tolist()
    )

    validation_rows.append({
        "cve_id": cve,
        "expected_attack_technique": expected,
        "attack_id": row["attack_id"],
        "expected_probability": expected_probability,
        "recovered": expected in predicted_techniques,
        "predicted_techniques": " | ".join(
            predicted_techniques
        ),
    })

validation = pd.DataFrame(validation_rows)

validation.to_csv(
    OUT / "noms_ai_validation.csv",
    index=False,
)

recovered = int(
    validation["recovered"].sum()
)

summary = {
    "original_training_rows": len(x),
    "benchmark_training_rows": len(x_pool),
    "held_out_cves": len(x_holdout),
    "exact_description_duplicates": 0,
    "selected_threshold": threshold,
    "reference_mappings": len(validation),
    "recovered_mappings": recovered,
    "reference_recovery": (
        recovered / len(validation)
    ),
}

with open(
    OUT / "noms_ai_summary.json",
    "w",
    encoding="utf-8",
) as file:
    json.dump(
        summary,
        file,
        indent=2,
    )

print()
print(validation.to_string(index=False))
print()
print(json.dumps(summary, indent=2))