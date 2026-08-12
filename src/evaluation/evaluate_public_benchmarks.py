from pathlib import Path
import json
import pandas as pd

BASE = Path("data/processed/benchmarks")

OUT = Path(
    "data/processed/lab/evaluation"
)

OUT.mkdir(parents=True, exist_ok=True)

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
        "validation_dimension": "Multi-stage sequence",
        "reference_items": darpa["total_stages"],
        "recovered_items": darpa["recovered_stages"],
        "recovery": darpa["stage_recovery"],
        "additional_result": (
            f"order_preserved={darpa['order_preserved']}"
        ),
    },
    {
        "benchmark": "MulVAL 3-host",
        "validation_dimension": "Graph structure",
        "reference_items": mulval["supported_checks"],
        "recovered_items": mulval["passed_checks"],
        "recovery": (
            mulval["passed_checks"]
            / mulval["supported_checks"]
        ),
        "additional_result": (
            "unsupported_relations="
            f"{mulval['unsupported_relation_count']}"
        ),
    },
    {
        "benchmark": "NOMS 2022",
        "validation_dimension": "CVE-to-ATT&CK context",
        "reference_items": noms["reference_mappings"],
        "recovered_items": noms["recovered_mappings"],
        "recovery": noms["reference_recovery"],
        "additional_result": (
            f"held_out_cves={noms['held_out_cves']}"
        ),
    },
]

results = pd.DataFrame(rows)

results.to_csv(
    OUT / "public_benchmark_evaluation.csv",
    index=False,
)

print(results.to_string(index=False))