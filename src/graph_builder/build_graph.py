from __future__ import annotations

from collections import Counter
from typing import Any

import networkx as nx

from utils.data_loader import (
    clean,
    load_access_conditions,
    load_assets,
    load_enriched_vulnerabilities,
    load_network_connections,
    load_services,
)

def safe_float(value: Any) -> float:
    """Convert a value to float, returning 0.0 when invalid."""

    try:
        return float(clean(value))
    except (TypeError, ValueError):
        return 0.0


def safe_int(value: Any) -> int | None:
    """Convert a port value to an integer."""

    try:
        return int(float(clean(value)))
    except (TypeError, ValueError):
        return None


def normalize_protocol(value: Any) -> str:
    return clean(value).lower()


def asset_node_id(asset_id: str) -> str:
    return f"ASSET|{asset_id}"


def service_node_id(
    ip_address: str,
    protocol: str,
    port: int,
) -> str:
    return f"SERVICE|{ip_address}|{protocol}|{port}"


def vulnerability_node_id(
    ip_address: str,
    protocol: str,
    port: int,
    identifier: str,
) -> str:
    safe_identifier = identifier.replace("|", "_")

    return (
        f"VULNERABILITY|{ip_address}|{protocol}|"
        f"{port}|{safe_identifier}"
    )

def access_condition_node_id(condition_id: str) -> str:
    return f"ACCESS_CONDITION|{condition_id}"

def build_attack_graph() -> nx.MultiDiGraph:
    """
    Build the attack graph from processed and manually defined datasets.

    Graph structure:

    attacker/asset
        -> service
        -> vulnerability
        -> compromised asset
    """

    graph = nx.MultiDiGraph(
        name="Automated Multi-Stage Attack Graph"
    )

    assets = load_assets()
    services = load_services()
    vulnerabilities = load_enriched_vulnerabilities()
    connections = load_network_connections()
    access_conditions = load_access_conditions()

    asset_by_ip: dict[str, str] = {}

    graph.add_node(
        "ATTACKER",
        node_type="attacker",
        label="External Attacker",
    )

    # -------------------------------------------------
    # Asset nodes
    # -------------------------------------------------

    for asset in assets:
        asset_id = clean(asset.get("asset_id"))
        ip_address = clean(asset.get("ip_address"))

        if not asset_id or not ip_address:
            continue

        node_id = asset_node_id(asset_id)
        asset_by_ip[ip_address] = node_id

        graph.add_node(
            node_id,
            node_type="asset",
            label=clean(asset.get("hostname")),
            asset_id=asset_id,
            ip_address=ip_address,
            hostname=clean(asset.get("hostname")),
            asset_type=clean(asset.get("asset_type")),
            zone=clean(asset.get("zone")),
            criticality=clean(asset.get("criticality")),
            criticality_score=safe_float(
                asset.get("criticality_score")
            ),
            is_entry_point=(
                clean(asset.get("is_entry_point")).lower()
                == "yes"
            ),
            is_primary_target=(
                clean(asset.get("is_primary_target")).lower()
                == "yes"
            ),
        )

    # -------------------------------------------------
    # Service nodes
    # -------------------------------------------------

    for service in services:
        ip_address = clean(service.get("ip_address"))
        protocol = normalize_protocol(service.get("protocol"))
        port = safe_int(service.get("port"))

        if (
            not ip_address
            or not protocol
            or port is None
            or ip_address not in asset_by_ip
        ):
            continue

        node_id = service_node_id(
            ip_address,
            protocol,
            port,
        )

        graph.add_node(
            node_id,
            node_type="service",
            label=(
                f"{ip_address}:{port}/{protocol} "
                f"{clean(service.get('service_name'))}"
            ).strip(),
            ip_address=ip_address,
            protocol=protocol,
            port=port,
            state=clean(service.get("state")),
            service_name=clean(service.get("service_name")),
            product=clean(service.get("product")),
            version=clean(service.get("version")),
            cpe=clean(service.get("cpe")),
        )

    # -------------------------------------------------
    # Aggregate vulnerability rows
    # -------------------------------------------------

    vulnerability_groups: dict[
        tuple[str, str, int, str],
        dict[str, Any],
    ] = {}

    skipped_findings = 0

    for finding in vulnerabilities:
        ip_address = clean(finding.get("ip_address"))
        protocol = normalize_protocol(finding.get("protocol"))
        port = safe_int(finding.get("port"))

        if not ip_address or not protocol or port is None:
            skipped_findings += 1
            continue

        service_id = service_node_id(
            ip_address,
            protocol,
            port,
        )

        # Only connect vulnerabilities to services
        # confirmed by Nmap.
        if service_id not in graph:
            skipped_findings += 1
            continue

        cve_id = clean(finding.get("cve_id")).upper()
        nvt_oid = clean(finding.get("nvt_oid"))
        result_id = clean(finding.get("result_id"))
        nvt_name = clean(finding.get("nvt_name"))

        identifier = (
            cve_id
            or nvt_oid
            or result_id
            or nvt_name
        )

        if not identifier:
            skipped_findings += 1
            continue

        key = (
            ip_address,
            protocol,
            port,
            identifier,
        )

        if key not in vulnerability_groups:
            vulnerability_groups[key] = {
                "ip_address": ip_address,
                "protocol": protocol,
                "port": port,
                "identifier": identifier,
                "cve_id": cve_id,
                "nvt_oid": nvt_oid,
                "nvt_names": set(),
                "openvas_cvss": 0.0,
                "nvd_cvss": 0.0,
                "epss": 0.0,
                "epss_percentile": 0.0,
                "kev": False,
                "severity": "",
                "nvd_cwes": set(),
            }

        group = vulnerability_groups[key]

        if nvt_name:
            group["nvt_names"].add(nvt_name)

        group["openvas_cvss"] = max(
            group["openvas_cvss"],
            safe_float(finding.get("cvss")),
        )

        group["nvd_cvss"] = max(
            group["nvd_cvss"],
            safe_float(finding.get("nvd_base_score")),
        )

        group["epss"] = max(
            group["epss"],
            safe_float(finding.get("epss")),
        )

        group["epss_percentile"] = max(
            group["epss_percentile"],
            safe_float(finding.get("epss_percentile")),
        )

        if clean(finding.get("kev")).lower() == "yes":
            group["kev"] = True

        severity = clean(finding.get("severity"))

        if severity:
            group["severity"] = severity

        for cwe in clean(finding.get("nvd_cwes")).split(";"):
            if cwe:
                group["nvd_cwes"].add(cwe)

    # -------------------------------------------------
    # Vulnerability nodes and exploit relationships
    # -------------------------------------------------

    for group in vulnerability_groups.values():
        ip_address = group["ip_address"]
        protocol = group["protocol"]
        port = group["port"]
        identifier = group["identifier"]

        vulnerability_id = vulnerability_node_id(
            ip_address,
            protocol,
            port,
            identifier,
        )

        service_id = service_node_id(
            ip_address,
            protocol,
            port,
        )

        target_asset_id = asset_by_ip.get(ip_address)

        if not target_asset_id:
            continue

        graph.add_node(
            vulnerability_id,
            node_type="vulnerability",
            label=group["cve_id"] or identifier,
            ip_address=ip_address,
            protocol=protocol,
            port=port,
            cve_id=group["cve_id"],
            nvt_oid=group["nvt_oid"],
            nvt_names=";".join(
                sorted(group["nvt_names"])
            ),
            openvas_cvss=group["openvas_cvss"],
            nvd_cvss=group["nvd_cvss"],
            epss=group["epss"],
            epss_percentile=group["epss_percentile"],
            kev=group["kev"],
            severity=group["severity"],
            nvd_cwes=";".join(
                sorted(group["nvd_cwes"])
            ),
        )

        graph.add_edge(
            service_id,
            vulnerability_id,
            edge_type="has_vulnerability",
        )

        graph.add_edge(
            vulnerability_id,
            target_asset_id,
            edge_type="compromises",
        )

    # -------------------------------------------------
    # Logical network reachability
    # -------------------------------------------------

    skipped_connections = 0

    for connection in connections:
        source = clean(connection.get("source"))
        target_ip = clean(connection.get("target"))
        protocol = normalize_protocol(
            connection.get("protocol")
        )
        port = safe_int(connection.get("port"))

        if not source or not target_ip or port is None:
            skipped_connections += 1
            continue

        if source == "external_attacker":
            source_node = "ATTACKER"
        else:
            source_node = asset_by_ip.get(source, "")

        target_service = service_node_id(
            target_ip,
            protocol,
            port,
        )

        if not source_node:
            skipped_connections += 1
            continue

        if target_service not in graph:
            skipped_connections += 1
            continue

        graph.add_edge(
            source_node,
            target_service,
            edge_type="can_reach",
            protocol=protocol,
            port=port,
            connection_type=clean(
                connection.get("connection_type")
            ),
            justification=clean(
                connection.get("justification")
            ),
        )

    # -------------------------------------------------
    # Credential and trust-based access conditions
    # -------------------------------------------------

    skipped_access_conditions = 0

    for condition in access_conditions:
        condition_id = clean(condition.get("condition_id"))
        source_ip = clean(condition.get("source_asset"))
        target_ip = clean(condition.get("target_asset"))
        protocol = normalize_protocol(condition.get("protocol"))
        port = safe_int(condition.get("port"))

        source_asset_node = asset_by_ip.get(source_ip)
        target_asset_node = asset_by_ip.get(target_ip)

        if (
            not condition_id
            or not source_asset_node
            or not target_asset_node
            or not protocol
            or port is None
        ):
            skipped_access_conditions += 1
            continue

        target_service_node = service_node_id(
            target_ip,
            protocol,
            port,
        )

        # The access condition must reference a service
        # confirmed by the Nmap dataset.
        if target_service_node not in graph:
            skipped_access_conditions += 1
            continue

        condition_node = access_condition_node_id(
            condition_id
        )

        graph.add_node(
            condition_node,
            node_type="access_condition",
            label=clean(condition.get("condition_type")),
            condition_id=condition_id,
            source_ip=source_ip,
            target_ip=target_ip,
            protocol=protocol,
            port=port,
            condition_type=clean(
                condition.get("condition_type")
            ),
            evidence_type=clean(
                condition.get("evidence_type")
            ),
            confidence=clean(condition.get("confidence")),
            description=clean(
                condition.get("description")
            ),
            target_service_node=target_service_node,
        )

        graph.add_edge(
            source_asset_node,
            condition_node,
            edge_type="requires_access_condition",
            protocol=protocol,
            port=port,
            evidence_type=clean(
                condition.get("evidence_type")
            ),
            confidence=clean(condition.get("confidence")),
        )

        graph.add_edge(
            condition_node,
            target_asset_node,
            edge_type="grants_access",
            protocol=protocol,
            port=port,
            condition_type=clean(
                condition.get("condition_type")
            ),
        )    

    graph.graph["skipped_findings"] = skipped_findings
    graph.graph["skipped_connections"] = skipped_connections

    graph.graph["skipped_access_conditions"] = (
    skipped_access_conditions
    )

    return graph


def get_graph_summary(
    graph: nx.MultiDiGraph,
) -> dict[str, int]:
    """Return counts of graph nodes and edges."""

    node_types = Counter(
        attributes.get("node_type", "unknown")
        for _, attributes in graph.nodes(data=True)
    )

    edge_types = Counter(
        attributes.get("edge_type", "unknown")
        for _, _, attributes in graph.edges(data=True)
    )

    return {
        "total_nodes": graph.number_of_nodes(),
        "total_edges": graph.number_of_edges(),
        "attacker_nodes": node_types["attacker"],
        "asset_nodes": node_types["asset"],
        "service_nodes": node_types["service"],
        "vulnerability_nodes": node_types["vulnerability"],
        "access_condition_nodes": node_types[
        "access_condition"
        ],
        "access_condition_requirement_edges": edge_types[
        "requires_access_condition"
        ],
        "access_grant_edges": edge_types["grants_access"],
        "skipped_access_conditions": graph.graph.get(
            "skipped_access_conditions",
            0,
        ),
        "reachability_edges": edge_types["can_reach"],
        "vulnerability_edges": edge_types[
            "has_vulnerability"
        ],
        "compromise_edges": edge_types["compromises"],
        "skipped_findings": graph.graph.get(
            "skipped_findings",
            0,
        ),
        "skipped_connections": graph.graph.get(
            "skipped_connections",
            0,
        ),
    }