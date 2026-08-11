from pathlib import Path
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt

BASE = Path("data/processed/lab/attack_paths")
ASSETS = Path("data/manual/assets.csv")
OUT = Path("images/attack_paths.png")

steps = pd.read_csv(BASE / "path_steps.csv")
assets = pd.read_csv(ASSETS)

# Repeated steps from different paths are removed.
steps = steps[
    ["source", "destination", "step_type"]
].drop_duplicates()

graph = nx.DiGraph()

# Valid attack transitions are added.
for _, row in steps.iterrows():
    graph.add_edge(
        row["source"],
        row["destination"],
        step_type=row["step_type"],
    )

# Asset names are used as readable labels.
labels = {
    f"asset:{row['ip']}": row["asset_name"]
    for _, row in assets.iterrows()
}

labels = {
    node: labels.get(node, node)
    for node in graph.nodes
}

# A reproducible layout is created.
pos = nx.spring_layout(graph, seed=42)

plt.figure(figsize=(10, 6))

nx.draw_networkx(
    graph,
    pos,
    labels=labels,
    node_size=3000,
    font_size=9,
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
    font_size=8,
)

plt.title("Validated Attack Paths to Critical Database")
plt.axis("off")
plt.tight_layout()

OUT.parent.mkdir(parents=True, exist_ok=True)
plt.savefig(OUT, dpi=300, bbox_inches="tight")
plt.close()

print(f"Visual nodes: {graph.number_of_nodes()}")
print(f"Visual edges: {graph.number_of_edges()}")
print(f"Saved: {OUT}")