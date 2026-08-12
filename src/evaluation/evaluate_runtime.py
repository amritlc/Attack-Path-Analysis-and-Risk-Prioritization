from pathlib import Path
import subprocess
import sys
import time

import pandas as pd


OUT = Path(
    "data/processed/lab/evaluation"
)

OUT.mkdir(parents=True, exist_ok=True)

STEPS = [
    (
        "attack_step_construction",
        "src.attack_graph.build_attack_steps",
    ),
    (
        "attack_path_generation",
        "src.attack_graph.generate_attack_paths",
    ),
    (
        "path_feature_extraction",
        "src.attack_graph.extract_path_features",
    ),
    (
        "chain_evidence",
        "src.risk_prioritization.build_chain_evidence",
    ),
    (
        "pareto_prioritisation",
        "src.risk_prioritization.pareto_prioritization",
    ),
    (
        "ai_attack_prediction",
        "src.risk_prioritization.predict_lab_attack_techniques",
    ),
    (
        "ai_path_context",
        "src.risk_prioritization.build_path_attack_context",
    ),
]

REPEATS = 5

rows = []

# Each analytical step is timed repeatedly.
for name, module in STEPS:
    times = []

    for run in range(1, REPEATS + 1):
        start = time.perf_counter()

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                module,
            ],
            capture_output=True,
            text=True,
        )

        elapsed = time.perf_counter() - start

        if result.returncode != 0:
            print(result.stderr)
            raise RuntimeError(
                f"{name} failed."
            )

        times.append(elapsed)

        rows.append({
            "step": name,
            "run": run,
            "execution_seconds": elapsed,
        })

    print(
        f"{name}: "
        f"{sum(times) / len(times):.4f} seconds mean"
    )

results = pd.DataFrame(rows)

results.to_csv(
    OUT / "runtime_runs.csv",
    index=False,
)

summary = (
    results.groupby("step")["execution_seconds"]
    .agg(
        mean_seconds="mean",
        median_seconds="median",
        min_seconds="min",
        max_seconds="max",
    )
    .reset_index()
)

summary.to_csv(
    OUT / "runtime_summary.csv",
    index=False,
)

pipeline_mean = summary["mean_seconds"].sum()

print()
print("Runtime summary:")
print(summary.to_string(index=False))

print()
print(
    f"Mean analytical pipeline runtime: "
    f"{pipeline_mean:.4f} seconds"
)
