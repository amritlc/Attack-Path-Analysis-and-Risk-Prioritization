from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab")
OUT = BASE / "evaluation"

OUT.mkdir(parents=True, exist_ok=True)

hosts = pd.read_csv(
    OUT / "host_baseline.csv"
)

paths = pd.read_csv(
    BASE / "attack_paths/attack_paths.csv"
)

steps = pd.read_csv(
    BASE / "attack_paths/path_steps.csv"
)

# Graph-path measurements are calculated.
total_paths = len(paths)

multi_stage_paths = (
    paths["hop_count"] > 1
).sum()

direct_paths = (
    paths["hop_count"] == 1
).sum()

candidate_steps = (
    steps["step_type"] == "candidate_compromise"
).sum()

target_steps = (
    steps["step_type"] == "target_reach"
).sum()

# Unique compromise transitions are counted.
candidate = steps[
    steps["step_type"] == "candidate_compromise"
]

unique_compromise_transitions = (
    candidate[
        ["source", "destination"]
    ]
    .drop_duplicates()
)

# The two analysis approaches are compared.
rows = [
    {
        "analysis_dimension": "Hosts with vulnerability evidence",
        "host_based": "Available",
        "graph_based": "Available",
        "graph_observation": "",
    },
    {
        "analysis_dimension": "Per-host CVSS evidence",
        "host_based": "Available",
        "graph_based": "Available",
        "graph_observation": "",
    },
    {
        "analysis_dimension": "Source-to-target paths",
        "host_based": "Not available",
        "graph_based": "Available",
        "graph_observation": total_paths,
    },
    {
        "analysis_dimension": "Multi-stage paths",
        "host_based": "Not available",
        "graph_based": "Available",
        "graph_observation": int(
            multi_stage_paths
        ),
    },
    {
        "analysis_dimension": "Direct target exposure",
        "host_based": "Not available",
        "graph_based": "Available",
        "graph_observation": int(
            direct_paths
        ),
    },
    {
        "analysis_dimension": "Candidate compromise steps",
        "host_based": "Not available",
        "graph_based": "Available",
        "graph_observation": int(
            candidate_steps
        ),
    },
    {
        "analysis_dimension": "Unique compromise transitions",
        "host_based": "Not available",
        "graph_based": "Available",
        "graph_observation": len(
            unique_compromise_transitions
        ),
    },
]

comparison = pd.DataFrame(rows)

comparison.to_csv(
    OUT / "host_vs_graph_comparison.csv",
    index=False,
)

metrics = pd.DataFrame([
    {
        "host_count": len(hosts),
        "path_count": total_paths,
        "multi_stage_path_count": int(
            multi_stage_paths
        ),
        "direct_target_path_count": int(
            direct_paths
        ),
        "path_step_count": len(steps),
        "candidate_compromise_steps": int(
            candidate_steps
        ),
        "unique_compromise_transitions": len(
            unique_compromise_transitions
        ),
        "target_reach_steps": int(
            target_steps
        ),
    }
])

metrics.to_csv(
    OUT / "host_graph_metrics.csv",
    index=False,
)

print("Comparison:")
print(comparison.to_string(index=False))

print()
print("Measured graph results:")
print(metrics.to_string(index=False))