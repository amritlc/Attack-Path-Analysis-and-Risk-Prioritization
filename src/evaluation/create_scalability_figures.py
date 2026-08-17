from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


SOURCE = Path(
    "data/processed/lab/evaluation/scalability_summary.csv"
)

OUT = Path("images/evaluation")
OUT.mkdir(parents=True, exist_ok=True)

data = pd.read_csv(SOURCE)


# Runtime growth is visualised.
plt.figure(figsize=(8, 5))

plt.plot(
    data["graph_nodes"],
    data["median_seconds"],
    marker="o",
)

plt.xlabel("Graph nodes")
plt.ylabel("Median execution time (seconds)")
plt.title(
    "Graph and Attack-Path Scalability"
)

plt.tight_layout()

plt.savefig(
    OUT / "scalability_runtime.png",
    dpi=300,
)

plt.close()


# Memory growth is visualised.
plt.figure(figsize=(8, 5))

plt.plot(
    data["graph_nodes"],
    data["mean_peak_memory_mb"],
    marker="o",
)

plt.xlabel("Graph nodes")
plt.ylabel("Mean peak memory (MB)")
plt.title(
    "Memory Usage During Scalability Evaluation"
)

plt.tight_layout()

plt.savefig(
    OUT / "scalability_memory.png",
    dpi=300,
)

plt.close()


print("Scalability figures generated.")