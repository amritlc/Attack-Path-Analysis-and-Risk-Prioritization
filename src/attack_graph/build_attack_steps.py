from pathlib import Path
import pandas as pd

GRAPH = Path("data/processed/lab/graph")
OUT = Path("data/processed/lab/attack_paths")
OUT.mkdir(parents=True, exist_ok=True)

nodes = pd.read_csv(GRAPH / "graph_nodes.csv")
edges = pd.read_csv(GRAPH / "graph_edges.csv")

# Relationship groups are selected.
reach = edges[edges["relation"] == "can_reach"]
hosted = edges[edges["relation"] == "hosts_service"]
vulns = edges[edges["relation"] == "has_vulnerability"]

target = nodes[
    (nodes["type"] == "asset") &
    (nodes["target"] == True)
]["node"].iloc[0]

steps = []

# Reachable services are converted into attack transitions.
for _, row in reach.iterrows():
    source = row["source"]
    service = row["target"]

    owner = hosted[hosted["target"] == service]

    if owner.empty:
        continue

    destination = owner.iloc[0]["source"]

    service_vulns = vulns[vulns["source"] == service]
    vuln_count = service_vulns["target"].nunique()

    if destination == target:
        step_type = "target_reach"
    elif vuln_count > 0:
        step_type = "candidate_compromise"
    else:
        continue

    steps.append({
        "source": source,
        "destination": destination,
        "service": service,
        "step_type": step_type,
        "vulnerability_count": vuln_count,
    })

data = pd.DataFrame(steps)
data.to_csv(OUT / "attack_steps.csv", index=False)

print(f"Attack transitions: {len(data)}")
print(f"Candidate compromise steps: {(data['step_type'] == 'candidate_compromise').sum()}")
print(f"Target reach steps: {(data['step_type'] == 'target_reach').sum()}")