from pathlib import Path
import pandas as pd

OUT = Path(
    "data/processed/benchmarks/mulval_3host"
)

OUT.mkdir(parents=True, exist_ok=True)

# Directly supported benchmark assets are recorded.
assets = pd.DataFrame([
    {"asset": "internet", "role": "attacker"},
    {"asset": "webServer", "role": "server"},
    {"asset": "fileServer", "role": "server"},
    {"asset": "workStation", "role": "target"},
])

# Directly defined services are recorded.
services = pd.DataFrame([
    {
        "asset": "webServer",
        "service": "httpd",
        "protocol": "tcp",
        "port": "80",
        "product": "apache",
    },
    {
        "asset": "fileServer",
        "service": "mountd",
        "protocol": "rpc",
        "port": "100005",
        "product": "",
    },
])

# Direct vulnerability relationships are recorded.
vulnerabilities = pd.DataFrame([
    {
        "asset": "webServer",
        "vulnerability": "CAN-2002-0392",
        "service": "httpd",
    },
    {
        "asset": "fileServer",
        "vulnerability": "vulID",
        "service": "mountd",
    },
])

# Only explicit concrete reachability is retained.
reachability = pd.DataFrame([
    {
        "source": "internet",
        "destination": "webServer",
        "protocol": "tcp",
        "port": "80",
    },
])

# MulVAL relationships outside the lab schema are preserved separately.
unsupported = pd.DataFrame([
    {
        "type": "nfs_export",
        "source": "fileServer",
        "destination": "workStation",
        "detail": "/export",
    },
    {
        "type": "nfs_export",
        "source": "fileServer",
        "destination": "webServer",
        "detail": "/export",
    },
    {
        "type": "nfs_mount",
        "source": "workStation",
        "destination": "fileServer",
        "detail": "/usr/local/share -> /export",
    },
])

assets.to_csv(
    OUT / "mulval_assets.csv",
    index=False,
)

services.to_csv(
    OUT / "mulval_services.csv",
    index=False,
)

vulnerabilities.to_csv(
    OUT / "mulval_vulnerabilities.csv",
    index=False,
)

reachability.to_csv(
    OUT / "mulval_reachability.csv",
    index=False,
)

unsupported.to_csv(
    OUT / "mulval_unsupported_relations.csv",
    index=False,
)

print(f"Assets: {len(assets)}")
print(f"Services: {len(services)}")
print(f"Vulnerabilities: {len(vulnerabilities)}")
print(f"Explicit reachability: {len(reachability)}")
print(f"Unsupported relations: {len(unsupported)}")