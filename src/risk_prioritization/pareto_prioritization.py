from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab/risk")

data = pd.read_csv(BASE / "chain_evidence.csv")

# Paths without compromise evidence are kept outside this comparison.
supported = data[
    data["compromise_steps"] > 0
].copy()

metrics = [
    "bottleneck_cvss",
    "bottleneck_epss",
    "kev_coverage",
]


def dominates(a, b):
    # All evidence values must be equal or stronger.
    no_worse = all(a[m] >= b[m] for m in metrics)

    # At least one evidence value must be stronger.
    better = any(a[m] > b[m] for m in metrics)

    return no_worse and better


remaining = supported.copy()
front_number = 1
fronts = {}

# Non-dominated evidence groups are extracted.
while not remaining.empty:
    current = []

    for i, row_a in remaining.iterrows():
        dominated = False

        for j, row_b in remaining.iterrows():
            if i == j:
                continue

            if dominates(row_b, row_a):
                dominated = True
                break

        if not dominated:
            current.append(i)

    for index in current:
        fronts[index] = front_number

    remaining = remaining.drop(current)
    front_number += 1

supported["evidence_front"] = supported.index.map(fronts)

# Direct exposure paths remain unranked.
unsupported = data[
    data["compromise_steps"] == 0
].copy()

unsupported["evidence_front"] = pd.NA

result = pd.concat(
    [supported, unsupported],
    ignore_index=True,
)

result = result.sort_values(
    ["evidence_front", "path_id"],
    na_position="last",
)

result.to_csv(
    BASE / "pareto_prioritization.csv",
    index=False,
)

print(result.to_string(index=False))