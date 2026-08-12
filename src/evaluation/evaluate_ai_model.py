from pathlib import Path
import json
import pandas as pd

MODEL = Path("models/cve2attack")

OUT = Path(
    "data/processed/lab/evaluation"
)

OUT.mkdir(parents=True, exist_ok=True)

with open(
    MODEL / "metrics.json",
    encoding="utf-8",
) as file:
    baseline = json.load(file)

with open(
    MODEL / "tuned_metrics.json",
    encoding="utf-8",
) as file:
    tuned = json.load(file)

rows = [
    {
        "model": "Default threshold",
        "micro_precision": baseline["micro_precision"],
        "micro_recall": baseline["micro_recall"],
        "micro_f1": baseline["micro_f1"],
        "macro_f1": baseline["macro_f1"],
        "hamming_loss": baseline["hamming_loss"],
    },
    {
        "model": "Validation-tuned threshold",
        "micro_precision": tuned["micro_precision"],
        "micro_recall": tuned["micro_recall"],
        "micro_f1": tuned["micro_f1"],
        "macro_f1": tuned["macro_f1"],
        "hamming_loss": tuned["hamming_loss"],
    },
]

comparison = pd.DataFrame(rows)

comparison["micro_f1_change"] = (
    comparison["micro_f1"]
    - comparison.iloc[0]["micro_f1"]
)

comparison.to_csv(
    OUT / "ai_model_comparison.csv",
    index=False,
)

print(comparison.to_string(index=False))