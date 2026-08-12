from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab/evaluation")
OUT = Path("experiments")

OUT.mkdir(parents=True, exist_ok=True)

graph = pd.read_csv(
    BASE / "host_graph_metrics.csv"
).iloc[0]

pareto = pd.read_csv(
    BASE / "cvss_pareto_summary.csv"
).iloc[0]

ablation = pd.read_csv(
    BASE / "ablation_summary.csv"
)

ai_model = pd.read_csv(
    BASE / "ai_model_comparison.csv"
)

ai_coverage = pd.read_csv(
    BASE / "ai_lab_coverage.csv"
).iloc[0]

benchmarks = pd.read_csv(
    BASE / "public_benchmark_evaluation.csv"
)

runtime = pd.read_csv(
    BASE / "pipeline_runtime_summary.csv"
).iloc[0]

rows = []

# Graph-analysis results are recorded.
rows.extend([
    {
        "experiment": "E01",
        "measure": "Source-to-target paths",
        "value": graph["path_count"],
    },
    {
        "experiment": "E01",
        "measure": "Multi-stage paths",
        "value": graph["multi_stage_path_count"],
    },
    {
        "experiment": "E01",
        "measure": "Candidate compromise steps",
        "value": graph["candidate_compromise_steps"],
    },
])

# Prioritisation results are recorded.
rows.extend([
    {
        "experiment": "E02",
        "measure": "CVSS top-group size",
        "value": pareto["cvss_top_group_size"],
    },
    {
        "experiment": "E02",
        "measure": "Pareto Front-1 size",
        "value": pareto["pareto_front1_size"],
    },
])

# Ablation results are recorded.
for _, row in ablation.iterrows():
    rows.append({
        "experiment": "E03",
        "measure": (
            f"Changed paths without "
            f"{row['removed_evidence']}"
        ),
        "value": row["changed_path_count"],
    })

# AI model results are recorded.
for _, row in ai_model.iterrows():
    rows.append({
        "experiment": "E04",
        "measure": f"{row['model']} Micro-F1",
        "value": row["micro_f1"],
    })

rows.append({
    "experiment": "E05",
    "measure": "Lab CVE prediction coverage",
    "value": ai_coverage["lab_prediction_coverage"],
})

# Public benchmark results are recorded.
for _, row in benchmarks.iterrows():
    rows.append({
        "experiment": "E06-E08",
        "measure": (
            f"{row['benchmark']} recovery"
        ),
        "value": row["recovery"],
    })

# Runtime results are recorded.
rows.extend([
    {
        "experiment": "E09",
        "measure": "Mean pipeline runtime seconds",
        "value": runtime["mean_seconds"],
    },
    {
        "experiment": "E09",
        "measure": "Median pipeline runtime seconds",
        "value": runtime["median_seconds"],
    },
])

results = pd.DataFrame(rows)

results.to_csv(
    OUT / "final_results.csv",
    index=False,
)

print(results.to_string(index=False))