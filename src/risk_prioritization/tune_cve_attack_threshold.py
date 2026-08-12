from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_recall_curve,
    precision_score,
    recall_score,
    f1_score,
    hamming_loss,
)

BASE = Path("data/processed/cve2attack")
MODEL = Path("models/cve2attack")

MODEL.mkdir(parents=True, exist_ok=True)

x_train = pd.read_csv(BASE / "X_train_clean.csv")
y_train = pd.read_csv(BASE / "y_train_clean.csv")

x_test = pd.read_csv(BASE / "X_test.csv")
y_test = pd.read_csv(BASE / "y_test.csv")

# A validation split is created from training data only.
x_fit, x_val, y_fit, y_val = train_test_split(
    x_train,
    y_train,
    test_size=0.2,
    random_state=42,
)

# TF-IDF features are created.
vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",
    ngram_range=(1, 2),
    max_features=10000,
)

fit_vectors = vectorizer.fit_transform(x_fit["Text"])
val_vectors = vectorizer.transform(x_val["Text"])

# One classifier is trained for each ATT&CK technique.
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

# Validation probabilities are generated.
val_probabilities = classifier.predict_proba(
    val_vectors
)

# The threshold is selected from validation data.
precision, recall, thresholds = precision_recall_curve(
    y_val.to_numpy().ravel(),
    val_probabilities.ravel(),
)

f1_values = (
    2 * precision * recall /
    (precision + recall + 1e-12)
)

best_index = np.argmax(f1_values[:-1])
best_threshold = float(thresholds[best_index])

print(f"Selected validation threshold: {best_threshold:.4f}")
print(f"Validation Micro-F1: {f1_values[best_index]:.4f}")

# The final model is trained on all clean training data.
vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",
    ngram_range=(1, 2),
    max_features=10000,
)

train_vectors = vectorizer.fit_transform(
    x_train["Text"]
)

test_vectors = vectorizer.transform(
    x_test["Text"]
)

classifier = OneVsRestClassifier(
    LogisticRegression(
        max_iter=1000,
        random_state=42,
    )
)

classifier.fit(
    train_vectors,
    y_train,
)

test_probabilities = classifier.predict_proba(
    test_vectors
)

predictions = (
    test_probabilities >= best_threshold
).astype(int)

metrics = {
    "training_rows": len(x_train),
    "test_rows": len(x_test),
    "attack_labels": y_train.shape[1],
    "selected_threshold": best_threshold,
    "micro_precision": precision_score(
        y_test,
        predictions,
        average="micro",
        zero_division=0,
    ),
    "micro_recall": recall_score(
        y_test,
        predictions,
        average="micro",
        zero_division=0,
    ),
    "micro_f1": f1_score(
        y_test,
        predictions,
        average="micro",
        zero_division=0,
    ),
    "macro_f1": f1_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0,
    ),
    "hamming_loss": hamming_loss(
        y_test,
        predictions,
    ),
}

joblib.dump(
    vectorizer,
    MODEL / "tfidf_vectorizer_tuned.joblib",
)

joblib.dump(
    classifier,
    MODEL / "attack_classifier_tuned.joblib",
)

with open(
    MODEL / "threshold.json",
    "w",
    encoding="utf-8",
) as file:
    json.dump(
        {"threshold": best_threshold},
        file,
        indent=2,
    )

with open(
    MODEL / "tuned_metrics.json",
    "w",
    encoding="utf-8",
) as file:
    json.dump(
        metrics,
        file,
        indent=2,
    )

print("\nTest results:")

for name, value in metrics.items():
    print(f"{name}: {value}")