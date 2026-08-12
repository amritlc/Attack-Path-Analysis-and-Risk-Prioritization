from pathlib import Path
import json
import pandas as pd

EVENTS = Path(
    "data/processed/benchmarks/darpa_lldos/darpa_events.csv"
)

REFERENCE = Path(
    "data/manual/benchmarks/darpa_lldos_reference.csv"
)

OUT = Path(
    "data/processed/benchmarks/darpa_lldos"
)

events = pd.read_csv(EVENTS)
reference = pd.read_csv(REFERENCE).fillna("")

results = []

# Each benchmark phase is checked against observed traffic.
for _, row in reference.iterrows():
    phase = int(row["phase"])

    targets = row["expected_targets"].split("|")
    services = row["expected_services"].split("|")

    matched = events[
        (events["phase"] == phase)
        & events["target_ip"].isin(targets)
        & events["service"].isin(services)
    ]

    source = row["expected_source"]

    if source:
        matched = matched[
            matched["source_ip"] == source
        ]

    matched_targets = matched["target_ip"].nunique()

    recovered = matched_targets == len(targets)

    results.append({
        "phase": phase,
        "reference_stage": row["reference_stage"],
        "matching_events": len(matched),
        "matched_targets": matched_targets,
        "expected_targets": len(targets),
        "recovered": recovered,
    })

validation = pd.DataFrame(results)

validation.to_csv(
    OUT / "darpa_stage_validation.csv",
    index=False,
)

# Chronological phase order is checked.
events["timestamp"] = pd.to_datetime(
    events["date"] + " " + events["time"],
    format="%m/%d/%Y %H:%M:%S",
)

phase_times = (
    events.groupby("phase")["timestamp"]
    .min()
    .sort_index()
)

order_preserved = phase_times.is_monotonic_increasing

recovered_stages = int(validation["recovered"].sum())
total_stages = len(validation)

summary = {
    "recovered_stages": recovered_stages,
    "total_stages": total_stages,
    "stage_recovery": recovered_stages / total_stages,
    "order_preserved": bool(order_preserved),
    "complete_campaign_sequence": bool(
        validation["recovered"].all()
        and order_preserved
    ),
}

with open(
    OUT / "darpa_validation_summary.json",
    "w",
    encoding="utf-8",
) as file:
    json.dump(summary, file, indent=2)

print(validation.to_string(index=False))
print()
print(json.dumps(summary, indent=2))