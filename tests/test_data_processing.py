from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab")
MANUAL = Path("data/manual")


def test_inventory_counts():
    hosts = pd.read_csv(BASE / "inventory/hosts.csv")
    services = pd.read_csv(BASE / "inventory/services.csv")

    # Expected inventory sizes are checked.
    assert len(hosts) == 8
    assert len(services) == 42


def test_openvas_processing():
    findings = pd.read_csv(BASE / "vulnerabilities/openvas_findings.csv")
    links = pd.read_csv(BASE / "vulnerabilities/finding_cve_links.csv")

    # OpenVAS and CVE counts are checked.
    assert findings["result_id"].nunique() == 136
    assert links["result_id"].nunique() == 80
    assert links["cve_id"].nunique() == 77
    assert len(links) == 154


def test_nvd_and_epss_coverage():
    nvd = pd.read_csv(BASE / "enrichment/nvd_enrichment.csv")
    epss = pd.read_csv(BASE / "enrichment/epss_enrichment.csv")

    # All lab CVEs should have NVD and EPSS data.
    assert nvd["nvd_found"].sum() == 77
    assert epss["epss_found"].sum() == 77


def test_kev_matching():
    kev = pd.read_csv(BASE / "enrichment/kev_enrichment.csv")

    # One lab CVE should be present in CISA KEV.
    assert kev["in_kev"].sum() == 1


def test_master_dataset():
    data = pd.read_csv(BASE / "master_vulnerabilities.csv")

    # The final dataset structure is checked.
    assert len(data) == 210
    assert data["result_id"].nunique() == 136
    assert data["cve_id"].nunique() == 77
    assert data.duplicated().sum() == 0


def test_asset_context():
    assets = pd.read_csv(MANUAL / "assets.csv")

    # One attacker and one critical target should exist.
    assert len(assets) == 5
    assert (assets["role"] == "attacker").sum() == 1
    assert assets["target"].sum() == 1


def test_connectivity():
    connections = pd.read_csv(MANUAL / "connectivity.csv")

    # All recorded connections were experimentally reachable.
    assert len(connections) == 13
    assert connections["reachable"].all()


def test_integration_quality():
    findings = pd.read_csv(BASE / "vulnerabilities/integrated_findings.csv")

    # Only one service finding should remain unmatched.
    unmatched = findings[
        findings["match_type"] == "unmatched_service"
    ]

    assert len(unmatched) == 1