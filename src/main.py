from pathlib import Path
import subprocess
import sys

import pandas as pd


STEPS = [
    ("Parse Nmap", "src.data_processing.parse_nmap"),
    ("Parse OpenVAS", "src.data_processing.parse_openvas"),
    ("Normalise CVEs", "src.data_processing.normalize_cves"),
    ("Integrate lab data", "src.data_processing.integrate_lab_data"),
    ("Enrich NVD", "src.data_processing.enrich_nvd"),
    ("Enrich EPSS", "src.data_processing.enrich_epss"),
    ("Enrich KEV", "src.data_processing.enrich_kev"),
    ("Build master dataset", "src.data_processing.build_master_dataset"),
    ("Validate lab data", "src.data_processing.validate_lab_data"),
    ("Build attack graph", "src.graph_builder.build_lab_graph"),
    ("Validate attack graph", "src.graph_builder.validate_lab_graph"),
    ("Build attack steps", "src.attack_graph.build_attack_steps"),
    ("Generate attack paths", "src.attack_graph.generate_attack_paths"),
    ("Extract path features", "src.attack_graph.extract_path_features"),
    ("Validate attack paths", "src.attack_graph.validate_attack_paths"),
    ("Build path evidence", "src.risk_prioritization.build_path_evidence"),
    ("Build CVSS baseline", "src.risk_prioritization.build_cvss_baseline"),
    ("Build chain evidence", "src.risk_prioritization.build_chain_evidence"),
    ("Pareto prioritisation", "src.risk_prioritization.pareto_prioritization"),
    ("Feature ablation", "src.risk_prioritization.feature_ablation"),
    ("Compare prioritisation", "src.risk_prioritization.compare_prioritization"),
    ("Validate prioritisation", "src.risk_prioritization.validate_prioritization"),
    ("Predict ATT&CK techniques", "src.risk_prioritization.predict_lab_attack_techniques"),
    ("Build ATT&CK path context", "src.risk_prioritization.build_path_attack_context"),
    ("Validate AI context", "src.risk_prioritization.validate_ai_context"),
    ("Visualise attack paths", "src.visualization.visualize_attack_paths"),
    ("Visualise ranked path", "src.visualization.visualize_ranked_path"),
]


def run_step(name, module):
    print(f"\n[{name}]")

    result = subprocess.run(
        [sys.executable, "-m", module]
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Pipeline stopped at: {name}"
        )


def print_summary():
    paths = pd.read_csv(
        "data/processed/lab/attack_paths/attack_paths.csv"
    )

    pareto = pd.read_csv(
        "data/processed/lab/risk/pareto_prioritization.csv"
    )

    predictions = pd.read_csv(
        "data/processed/lab/risk/lab_attack_prediction_summary.csv"
    )

    multi_stage = (
        paths["hop_count"] > 1
    ).sum()

    front1 = pareto[
        pareto["evidence_front"] == 1
    ]["path_id"].tolist()

    predicted = (
        predictions["prediction_count"] > 0
    ).sum()

    print("\nFramework completed successfully.")
    print(f"Attack paths: {len(paths)}")
    print(f"Multi-stage paths: {multi_stage}")
    print(
        "Highest-priority Pareto path: "
        + " | ".join(front1)
    )
    print(
        f"AI CVEs analysed: {len(predictions)}"
    )
    print(
        f"AI predictions available: {predicted}"
    )


def main():
    print(
        "Automated Multi-Stage Attack Path Analysis "
        "and AI-Assisted Risk Prioritization"
    )

    for name, module in STEPS:
        run_step(name, module)

    print_summary()


if __name__ == "__main__":
    main()