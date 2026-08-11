from pathlib import Path
import pandas as pd
import networkx as nx

BASE = Path("data/processed/lab")
MANUAL = Path("data/manual")

graph = nx.read_graphml(BASE / "graph/attack_graph.graphml")
nodes = pd.read_csv(BASE / "graph/graph_nodes.csv")
edges = pd.read_csv(BASE / "graph/graph_edges.csv")

assets = pd.read_csv(MANUAL / "assets.csv")
services = pd.read_csv(BASE / "inventory/services.csv")
connections = pd.read_csv(MANUAL / "connectivity.csv")

asset_nodes = set(nodes[nodes["type"] == "asset"]["node"])
service_nodes = set(nodes[nodes["type"] == "service"]["node"])
vuln_nodes = set(nodes[nodes["type"] == "vulnerability"]["node"])

# Relationship groups are selected.
hosted = edges[edges["relation"] == "hosts_service"]
reachable = edges[edges["relation"] == "can_reach"]
has_vuln = edges[edges["relation"] == "has_vulnerability"]
affects = edges[edges["relation"] == "affects"]

checks = {
    "graph_is_directed": graph.is_directed(),
    "all_assets_present": len(asset_nodes) == len(assets),
    "all_services_present": len(service_nodes) == len(services),
    "all_services_have_host": set(hosted["target"]) == service_nodes,
    "all_vulnerabilities_linked": set(has_vuln["target"]) == vuln_nodes,
    "all_vulnerabilities_affect_asset": set(affects["source"]) == vuln_nodes,
    "connectivity_preserved": len(reachable) == connections["reachable"].sum(),
    "one_attacker": (nodes["role"] == "attacker").sum() == 1,
    "one_target": nodes["target"].eq(True).sum() == 1,
}

# Every graph check must pass.
for name, passed in checks.items():
    print(f"{name}: {passed}")

if not all(checks.values()):
    raise ValueError("Graph validation failed.")

print("Graph validation passed.")