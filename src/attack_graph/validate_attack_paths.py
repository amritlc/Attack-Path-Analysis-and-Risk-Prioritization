from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab/attack_paths")

paths = pd.read_csv(BASE / "attack_paths.csv")
steps = pd.read_csv(BASE / "attack_steps.csv")
details = pd.read_csv(BASE / "path_steps.csv")
features = pd.read_csv(BASE / "path_features.csv")

attacker = "asset:192.168.100.6"
target = "asset:192.168.100.5"

checks = {}

# All paths must start from the attacker.
checks["all_start_from_attacker"] = (
    paths["source"] == attacker
).all()

# All paths must finish at the critical target.
checks["all_reach_target"] = (
    paths["target"] == target
).all()

# Path identifiers must be unique.
checks["unique_path_ids"] = paths["path_id"].is_unique

# Repeated assets must not exist inside a path.
checks["no_cycles"] = all(
    len(items := path.split(" > ")) == len(set(items))
    for path in paths["asset_path"]
)

# Every recorded step must exist in the transition dataset.
valid_steps = set(zip(steps["source"], steps["destination"]))

checks["all_steps_valid"] = all(
    (row["source"], row["destination"]) in valid_steps
    for _, row in details.iterrows()
)

# Every path must have one feature row.
checks["all_paths_have_features"] = (
    set(paths["path_id"]) == set(features["path_id"])
)

# The expected lab scenario contains five paths.
checks["expected_path_count"] = len(paths) == 5

for name, passed in checks.items():
    print(f"{name}: {passed}")

if not all(checks.values()):
    raise ValueError("Attack path validation failed.")

print("Attack path validation passed.")