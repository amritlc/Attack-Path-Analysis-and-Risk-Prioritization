from pathlib import Path
import json
import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    hamming_loss,
)

BASE = Path("data/processed/cve2attack")
MODEL = Path("models/cve2attack")

MODEL.mkdir(parents=True, exist_ok=True)

x_train = pd.read_csv(
    BASE / "X_train_clean.csv"
)

y_train = pd.read_csv(
    BASE / "y_train_clean.csv"
)

x_test = pd.read_csv(
    BASE / "X_test.csv"
)

y_test = pd.read_csv(
    BASE / "y_test.csv"
)

# CVE descriptions are converted into TF-IDF features.
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

# One binary classifier is trained for each ATT&CK technique.
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

# Default classifier predictions are generated.
predictions = classifier.predict(
    test_vectors
)

metrics = {
    "training_rows": len(x_train),
    "test_rows": len(x_test),
    "attack_labels": y_train.shape[1],
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

# Model components are saved.
joblib.dump(
    vectorizer,
    MODEL / "tfidf_vectorizer.joblib",
)

joblib.dump(
    classifier,
    MODEL / "attack_classifier.joblib",
)

with open(
    MODEL / "metrics.json",
    "w",
    encoding="utf-8",
) as file:
    json.dump(
        metrics,
        file,
        indent=2,
    )

print("Model training complete.")
print()

for name, value in metrics.items():
    print(f"{name}: {value}")