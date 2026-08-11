from pathlib import Path
import pandas as pd
import networkx as nx

INPUT = Path("data/processed/lab/attack_paths/attack_steps.csv")
OUT = Path("data/processed/lab/attack_paths/attack_paths.csv")

steps = pd.read_csv(INPUT)
graph = nx.DiGraph()

# Attack transitions are added to a reduced graph.
for _, row in steps.iterrows():
    graph.add_edge(
        row["source"],
        row["destination"],
        service=row["service"],
        step_type=row["step_type"],
        vulnerability_count=int(row["vulnerability_count"]),
    )

attacker = "asset:192.168.100.6"
target = "asset:192.168.100.5"

# Simple paths prevent repeated assets and cycles.
paths = list(nx.all_simple_paths(graph, attacker, target))

rows = []

for number, path in enumerate(paths, start=1):
    rows.append({
        "path_id": f"P{number:03}",
        "source": path[0],
        "target": path[-1],
        "hop_count": len(path) - 1,
        "asset_path": " > ".join(path),
    })

pd.DataFrame(rows).to_csv(OUT, index=False)

print(f"Attack paths: {len(rows)}")

for row in rows:
    print(f"{row['path_id']}: {row['asset_path']}")