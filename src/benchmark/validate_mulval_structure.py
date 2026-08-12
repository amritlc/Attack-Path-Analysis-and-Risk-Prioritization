from pathlib import Path
import json
import pandas as pd

BASE = Path(
    "data/processed/benchmarks/mulval_3host"
)

assets = pd.read_csv(BASE / "mulval_assets.csv")
services = pd.read_csv(BASE / "mulval_services.csv")
vulnerabilities = pd.read_csv(
    BASE / "mulval_vulnerabilities.csv"
)
reachability = pd.read_csv(
    BASE / "mulval_reachability.csv"
)
unsupported = pd.read_csv(
    BASE / "mulval_unsupported_relations.csv"
)

checks = {}

# Required benchmark assets are checked.
checks["assets_present"] = set(assets["asset"]) == {
    "internet",
    "webServer",
    "fileServer",
    "workStation",
}

# The benchmark target is checked.
checks["target_present"] = (
    assets.loc[
        assets["asset"] == "workStation",
        "role",
    ].iloc[0]
    == "target"
)

# Directly defined services are checked.
checks["services_present"] = (
    len(services) == 2
)

# Direct vulnerabilities are checked.
checks["vulnerabilities_present"] = (
    len(vulnerabilities) == 2
)

# The explicit Internet-to-web path is checked.
explicit = reachability[
    (reachability["source"] == "internet")
    & (reachability["destination"] == "webServer")
    & (reachability["protocol"] == "tcp")
    & (reachability["port"] == 80)
]

checks["internet_web_reachability"] = (
    len(explicit) == 1
)

# The known web vulnerability is checked.
web_vuln = vulnerabilities[
    (vulnerabilities["asset"] == "webServer")
    & (
        vulnerabilities["vulnerability"]
        == "CAN-2002-0392"
    )
]

checks["web_vulnerability_present"] = (
    len(web_vuln) == 1
)

# Unsupported MulVAL semantics must remain documented.
checks["unsupported_relations_preserved"] = (
    len(unsupported) == 3
)

for name, passed in checks.items():
    print(f"{name}: {passed}")

summary = {
    "supported_checks": len(checks),
    "passed_checks": sum(checks.values()),
    "all_supported_structure_recovered": all(
        checks.values()
    ),
    "unsupported_relation_count": len(unsupported),
}

with open(
    BASE / "mulval_validation_summary.json",
    "w",
    encoding="utf-8",
) as file:
    json.dump(summary, file, indent=2)

print()
print(json.dumps(summary, indent=2))

if not all(checks.values()):
    raise ValueError(
        "MulVAL structural validation failed."
    )