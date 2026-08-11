from pathlib import Path
import pandas as pd
import networkx as nx

BASE = Path("data/processed/lab")
MANUAL = Path("data/manual")
OUT = BASE / "graph"

OUT.mkdir(parents=True, exist_ok=True)

assets = pd.read_csv(MANUAL / "assets.csv")
services = pd.read_csv(BASE / "inventory/services.csv")
connections = pd.read_csv(MANUAL / "connectivity.csv")
data = pd.read_csv(BASE / "master_vulnerabilities.csv")

graph = nx.DiGraph()

# Asset nodes are added.
for _, row in assets.iterrows():
    graph.add_node(
        f"asset:{row['ip']}",
        type="asset",
        ip=row["ip"],
        name=row["asset_name"],
        role=row["role"],
        criticality=row["criticality"],
        target=bool(row["target"]),
    )

# Service nodes are added and linked to their hosts.
for _, row in services.iterrows():
    service_node = (
        f"service:{row['ip']}:{row['port']}:{row['protocol']}"
    )

    graph.add_node(
        service_node,
        type="service",
        ip=row["ip"],
        port=int(row["port"]),
        protocol=row["protocol"],
        service=row["service"],
        product=row["product"],
    )

    asset_node = f"asset:{row['ip']}"

    if asset_node in graph:
        graph.add_edge(
            asset_node,
            service_node,
            relation="hosts_service",
        )

# Verified network reachability is added.
for _, row in connections.iterrows():
    if not row["reachable"]:
        continue

    service_node = (
        f"service:{row['destination_ip']}:"
        f"{row['port']}:{row['protocol']}"
    )

    if service_node in graph:
        graph.add_edge(
            f"asset:{row['source_ip']}",
            service_node,
            relation="can_reach",
        )

# Service-level vulnerabilities are added.
matched = data[data["match_type"] == "service_match"]

for _, row in matched.iterrows():
    service_node = (
        f"service:{row['ip']}:"
        f"{int(row['port'])}:{row['protocol']}"
    )

    if service_node not in graph:
        continue

    vuln_id = (
        row["cve_id"]
        if pd.notna(row["cve_id"])
        else row["result_id"]
    )

    vuln_node = f"vuln:{row['ip']}:{vuln_id}"

    graph.add_node(
        vuln_node,
        type="vulnerability",
        cve=str(row["cve_id"]) if pd.notna(row["cve_id"]) else "",
        nvt=row["nvt_name"],
        cvss=float(row["cvss_score"]) if pd.notna(row["cvss_score"]) else 0.0,
        epss=float(row["epss"]) if pd.notna(row["epss"]) else 0.0,
        kev=bool(row["in_kev"]) if pd.notna(row["in_kev"]) else False,
    )

    graph.add_edge(
        service_node,
        vuln_node,
        relation="has_vulnerability",
    )

    graph.add_edge(
        vuln_node,
        f"asset:{row['ip']}",
        relation="affects",
    )

# The graph is exported.
nx.write_graphml(graph, OUT / "attack_graph.graphml")

nodes = pd.DataFrame([
    {"node": node, **values}
    for node, values in graph.nodes(data=True)
])

edges = pd.DataFrame([
    {"source": source, "target": target, **values}
    for source, target, values in graph.edges(data=True)
])

nodes.to_csv(OUT / "graph_nodes.csv", index=False)
edges.to_csv(OUT / "graph_edges.csv", index=False)

print(f"Graph nodes: {graph.number_of_nodes()}")
print(f"Graph edges: {graph.number_of_edges()}")