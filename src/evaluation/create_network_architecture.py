from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd


ASSETS = Path("data/manual/assets.csv")
CONNECTIVITY = Path("data/manual/connectivity.csv")
OUT = Path("images/evaluation")

OUT.mkdir(parents=True, exist_ok=True)

assets = pd.read_csv(ASSETS)
links = pd.read_csv(CONNECTIVITY)

# Only verified reachable connections are used.
links = links[
    links["reachable"] == True
].copy()

graph = nx.DiGraph()

# Asset nodes are added.
for _, row in assets.iterrows():
    graph.add_node(
        row["ip"],
        name=row["asset_name"],
        role=row["role"],
        target=row["target"],
    )

# Verified reachability edges are added.
for _, row in links.iterrows():
    graph.add_edge(
        row["source_ip"],
        row["destination_ip"],
        label=f"{row['port']}/{row['protocol']}",
    )

# Positions are used only for readability.
positions = {
    "192.168.100.6": (0, 0),
    "192.168.100.4": (1, 1),
    "192.168.100.7": (1, 0),
    "192.168.100.8": (1, -1),
    "192.168.100.5": (2, 0),
}

labels = {}

for _, row in assets.iterrows():
    text = (
        f"{row['asset_name']}\n"
        f"{row['ip']}"
    )

    if row["role"] == "attacker":
        text += "\nATTACKER"

    if row["target"] == True:
        text += "\nCRITICAL TARGET"

    labels[row["ip"]] = text

plt.figure(figsize=(12, 7))

nx.draw_networkx_nodes(
    graph,
    positions,
    node_size=3200,
)

nx.draw_networkx_edges(
    graph,
    positions,
    arrows=True,
    arrowsize=18,
    connectionstyle="arc3,rad=0.08",
)

nx.draw_networkx_labels(
    graph,
    positions,
    labels=labels,
    font_size=8,
)

edge_labels = nx.get_edge_attributes(
    graph,
    "label",
)

nx.draw_networkx_edge_labels(
    graph,
    positions,
    edge_labels=edge_labels,
    font_size=7,
)

plt.title(
    "Experimental Network Architecture "
    "and Verified Reachability"
)

plt.text(
    1,
    -1.55,
    "Edges represent experimentally verified reachability. "
    "Node positions are for visual readability only.",
    ha="center",
    fontsize=8,
)

plt.axis("off")
plt.tight_layout()

plt.savefig(
    OUT / "experimental_network_architecture.png",
    dpi=300,
    bbox_inches="tight",
)

plt.close()

print(
    "Generated:",
    OUT / "experimental_network_architecture.png",
)