from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import networkx as nx


BASE = Path("data/processed/lab/evaluation")
PATH_BASE = Path("data/processed/lab/attack_paths")
RISK_BASE = Path("data/processed/lab/risk")
OUT = Path("images/evaluation")

OUT.mkdir(parents=True, exist_ok=True)


# -------------------------------------------------
# 1. Attack-path overview
# -------------------------------------------------

paths = pd.read_csv(
    PATH_BASE / "attack_paths.csv"
)

graph = nx.DiGraph()

for _, row in paths.iterrows():
    nodes = [
        item.replace("asset:", "")
        for item in row["asset_path"].split(" > ")
    ]

    for source, target in zip(
        nodes[:-1],
        nodes[1:],
    ):
        graph.add_edge(source, target)

positions = nx.spring_layout(
    graph,
    seed=42,
)

plt.figure(figsize=(10, 6))

nx.draw_networkx(
    graph,
    positions,
    with_labels=True,
    node_size=2200,
    font_size=9,
    arrows=True,
)

plt.title(
    "Generated Attack-Path Structure"
)
plt.axis("off")
plt.tight_layout()

plt.savefig(
    OUT / "attack_path_overview.png",
    dpi=300,
)

plt.close()


# -------------------------------------------------
# 2. Feature-ablation result
# -------------------------------------------------

ablation = pd.read_csv(
    RISK_BASE / "feature_ablation.csv"
)

plot_data = ablation.set_index(
    "path_id"
)[
    [
        "full",
        "without_cvss",
        "without_epss",
        "without_kev",
    ]
].T

plt.figure(figsize=(9, 6))

plot_data.plot(
    kind="bar",
    ax=plt.gca(),
)

plt.ylabel("Pareto front")
plt.xlabel("Evidence configuration")
plt.title(
    "Effect of Single-Feature Ablation "
    "on Pareto Prioritisation"
)

plt.xticks(
    rotation=0
)

plt.gca().invert_yaxis()

plt.tight_layout()

plt.savefig(
    OUT / "ablation_effect.png",
    dpi=300,
)

plt.close()


# -------------------------------------------------
# 3. AI prediction coverage by path
# -------------------------------------------------

coverage = pd.read_csv(
    BASE / "ai_path_coverage.csv"
)

coverage = coverage[
    coverage["observed_cve_count"] > 0
].copy()

coverage["coverage_percent"] = (
    coverage["prediction_coverage"] * 100
)

plt.figure(figsize=(8, 5))

plt.bar(
    coverage["path_id"],
    coverage["coverage_percent"],
)

plt.ylabel("Prediction coverage (%)")
plt.xlabel("Attack path")
plt.title(
    "AI-Assisted ATT&CK Prediction Coverage"
)

plt.ylim(0, 100)

plt.tight_layout()

plt.savefig(
    OUT / "ai_path_coverage.png",
    dpi=300,
)

plt.close()


print("Additional figures generated:")
print(OUT / "attack_path_overview.png")
print(OUT / "ablation_effect.png")
print(OUT / "ai_path_coverage.png")