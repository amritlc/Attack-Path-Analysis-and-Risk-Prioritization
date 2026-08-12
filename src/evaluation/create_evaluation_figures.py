from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

BASE = Path("data/processed/lab/evaluation")
OUT = Path("images/evaluation")

OUT.mkdir(parents=True, exist_ok=True)


# CVSS and Pareto top groups are compared.
pareto = pd.read_csv(
    BASE / "cvss_pareto_summary.csv"
).iloc[0]

labels = [
    "CVSS-only",
    "Pareto Front 1",
]

values = [
    pareto["cvss_top_group_size"],
    pareto["pareto_front1_size"],
]

plt.figure(figsize=(7, 5))
plt.bar(labels, values)
plt.ylabel("Number of top-priority paths")
plt.title("CVSS-Only vs Pareto Prioritisation")
plt.tight_layout()
plt.savefig(
    OUT / "cvss_vs_pareto.png",
    dpi=300,
)
plt.close()


# Default and tuned ML metrics are compared.
ai = pd.read_csv(
    BASE / "ai_model_comparison.csv"
)

metrics = [
    "micro_precision",
    "micro_recall",
    "micro_f1",
    "macro_f1",
]

plot_data = ai.set_index("model")[metrics].T

plt.figure(figsize=(9, 5))
plot_data.plot(
    kind="bar",
    ax=plt.gca(),
)
plt.ylabel("Score")
plt.xlabel("Metric")
plt.title(
    "Default vs Validation-Tuned "
    "ATT&CK Classifier"
)
plt.xticks(rotation=0)
plt.tight_layout()
plt.savefig(
    OUT / "ai_model_comparison.png",
    dpi=300,
)
plt.close()


# Runtime of each analytical stage is shown.
runtime = pd.read_csv(
    BASE / "runtime_summary.csv"
).sort_values(
    "mean_seconds"
)

plt.figure(figsize=(9, 6))
plt.barh(
    runtime["step"],
    runtime["mean_seconds"],
)
plt.xlabel("Mean execution time (seconds)")
plt.title("Analytical Pipeline Runtime by Stage")
plt.tight_layout()
plt.savefig(
    OUT / "runtime_by_stage.png",
    dpi=300,
)
plt.close()

print("Evaluation figures generated.")
print(OUT)