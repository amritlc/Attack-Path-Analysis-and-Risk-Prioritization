from pathlib import Path
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt

BASE = Path("data/processed/lab")
OUT = Path("images/highest_priority_attack_path.png")

comparison = pd.read_csv(
    BASE / "risk/prioritization_comparison.csv"
)

assets = pd.read_csv(
    "data/manual/assets.csv"
)

steps = pd.read_csv(
    BASE / "attack_paths/path_steps.csv"
)

# The first evidence front is selected.
top = comparison[
    comparison["evidence_front"] == 1
].iloc[0]

path_id = top["path_id"]

path_steps = steps[
    steps["path_id"] == path_id
]

graph = nx.DiGraph()

# Path transitions are added.
for _, row in path_steps.iterrows():
    graph.add_edge(
        row["source"],
        row["destination"],
        step_type=row["step_type"],
    )

# Readable asset labels are created.
labels = {
    f"asset:{row['ip']}": row["asset_name"]
    for _, row in assets.iterrows()
}

labels = {
    node: labels.get(node, node)
    for node in graph.nodes
}

# A simple left-to-right layout is used.
nodes = list(graph.nodes)

pos = {
    node: (index, 0)
    for index, node in enumerate(nodes)
}

plt.figure(figsize=(10, 5))

nx.draw_networkx(
    graph,
    pos,
    labels=labels,
    node_size=3500,
    font_size=10,
    arrows=True,
)

edge_labels = {
    (source, target): data["step_type"].replace("_", " ")
    for source, target, data in graph.edges(data=True)
}

nx.draw_networkx_edge_labels(
    graph,
    pos,
    edge_labels=edge_labels,
    font_size=9,
)

evidence = (
    f"{path_id} | Evidence Front 1\n"
    f"Bottleneck CVSS: {top['bottleneck_cvss']}\n"
    f"Bottleneck EPSS: {top['bottleneck_epss']}\n"
    f"KEV Coverage: {top['kev_coverage']}"
)

plt.text(
    0.5,
    -0.35,
    evidence,
    transform=plt.gca().transAxes,
    ha="center",
    fontsize=10,
)

plt.title(
    "Highest-Priority Evidence-Supported Attack Path"
)

plt.axis("off")
plt.tight_layout()

OUT.parent.mkdir(parents=True, exist_ok=True)

plt.savefig(
    OUT,
    dpi=300,
    bbox_inches="tight",
)

plt.close()

print(f"Selected path: {path_id}")
print(f"Saved: {OUT}")