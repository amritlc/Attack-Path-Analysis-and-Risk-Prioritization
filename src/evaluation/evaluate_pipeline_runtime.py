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
    "src.attack_graph.build_attack_steps",
    "src.attack_graph.generate_attack_paths",
    "src.attack_graph.extract_path_features",
    "src.risk_prioritization.build_chain_evidence",
    "src.risk_prioritization.pareto_prioritization",
    "src.risk_prioritization.predict_lab_attack_techniques",
    "src.risk_prioritization.build_path_attack_context",
]

REPEATS = 5

rows = []

# The complete analytical pipeline is timed.
for run in range(1, REPEATS + 1):
    start = time.perf_counter()

    for module in STEPS:
        result = subprocess.run(
            [sys.executable, "-m", module],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print(result.stderr)
            raise RuntimeError(
                f"{module} failed."
            )

    elapsed = time.perf_counter() - start

    rows.append({
        "run": run,
        "execution_seconds": elapsed,
    })

    print(
        f"Run {run}: {elapsed:.4f} seconds"
    )

results = pd.DataFrame(rows)

results.to_csv(
    OUT / "pipeline_runtime_runs.csv",
    index=False,
)

summary = pd.DataFrame([
    {
        "runs": len(results),
        "mean_seconds": results[
            "execution_seconds"
        ].mean(),
        "median_seconds": results[
            "execution_seconds"
        ].median(),
        "min_seconds": results[
            "execution_seconds"
        ].min(),
        "max_seconds": results[
            "execution_seconds"
        ].max(),
    }
])

summary.to_csv(
    OUT / "pipeline_runtime_summary.csv",
    index=False,
)

print()
print("Pipeline runtime summary:")
print(summary.to_string(index=False))