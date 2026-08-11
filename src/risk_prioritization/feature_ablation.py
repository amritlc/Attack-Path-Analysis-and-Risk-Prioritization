from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab/risk")

data = pd.read_csv(BASE / "chain_evidence.csv")
data = data[data["compromise_steps"] > 0].copy()

experiments = {
    "full": [
        "bottleneck_cvss",
        "bottleneck_epss",
        "kev_coverage",
    ],
    "without_cvss": [
        "bottleneck_epss",
        "kev_coverage",
    ],
    "without_epss": [
        "bottleneck_cvss",
        "kev_coverage",
    ],
    "without_kev": [
        "bottleneck_cvss",
        "bottleneck_epss",
    ],
}


def get_fronts(frame, metrics):
    remaining = frame.copy()
    fronts = {}
    front_number = 1

    while not remaining.empty:
        current = []

        for i, a in remaining.iterrows():
            dominated = False

            for j, b in remaining.iterrows():
                if i == j:
                    continue

                no_worse = all(
                    b[m] >= a[m] for m in metrics
                )

                better = any(
                    b[m] > a[m] for m in metrics
                )

                if no_worse and better:
                    dominated = True
                    break

            if not dominated:
                current.append(i)

        for index in current:
            fronts[index] = front_number

        remaining = remaining.drop(current)
        front_number += 1

    return fronts


result = data[["path_id"]].copy()

# Each evidence dimension is removed once.
for name, metrics in experiments.items():
    fronts = get_fronts(data, metrics)
    result[name] = data.index.map(fronts)

result.to_csv(
    BASE / "feature_ablation.csv",
    index=False,
)

print(result.to_string(index=False))