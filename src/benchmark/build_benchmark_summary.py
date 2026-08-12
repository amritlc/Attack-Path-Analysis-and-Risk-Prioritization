from pathlib import Path
import json
import pandas as pd

BASE = Path("data/processed/benchmarks")

with open(
    BASE / "darpa_lldos/darpa_validation_summary.json",
    encoding="utf-8",
) as file:
    darpa = json.load(file)

with open(
    BASE / "mulval_3host/mulval_validation_summary.json",
    encoding="utf-8",
) as file:
    mulval = json.load(file)

with open(
    BASE / "noms2022/noms_ai_summary.json",
    encoding="utf-8",
) as file:
    noms = json.load(file)

rows = [
    {
        "benchmark": "DARPA LLDOS 1.0",
        "component_validated": "Multi-stage sequence recovery",
        "result": (
            f"{darpa['recovered_stages']}/"
            f"{darpa['total_stages']} stages"
        ),
        "recovery": darpa["stage_recovery"],
        "passed": darpa["complete_campaign_sequence"],
    },
    {
        "benchmark": "MulVAL 3-host",
        "component_validated": "Graph structural compatibility",
        "result": (
            f"{mulval['passed_checks']}/"
            f"{mulval['supported_checks']} checks"
        ),
        "recovery": (
            mulval["passed_checks"]
            / mulval["supported_checks"]
        ),
        "passed": (
            mulval["all_supported_structure_recovered"]
        ),
    },
    {
        "benchmark": "NOMS 2022",
        "component_validated": "CVE-to-ATT&CK AI context",
        "result": (
            f"{noms['recovered_mappings']}/"
            f"{noms['reference_mappings']} mappings"
        ),
        "recovery": noms["reference_recovery"],
        "passed": (
            noms["recovered_mappings"]
            == noms["reference_mappings"]
        ),
    },
]

summary = pd.DataFrame(rows)

summary.to_csv(
    BASE / "benchmark_summary.csv",
    index=False,
)

print(summary.to_string(index=False))