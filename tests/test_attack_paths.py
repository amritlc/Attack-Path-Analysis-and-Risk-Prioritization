from pathlib import Path
import pandas as pd

BASE = Path("data/processed/lab/attack_paths")

paths = pd.read_csv(BASE / "attack_paths.csv")
steps = pd.read_csv(BASE / "attack_steps.csv")
details = pd.read_csv(BASE / "path_steps.csv")
features = pd.read_csv(BASE / "path_features.csv")

ATTACKER = "asset:192.168.100.6"
TARGET = "asset:192.168.100.5"


def test_attack_path_count():
    # Five valid paths are expected.
    assert len(paths) == 5


def test_all_paths_start_from_attacker():
    # Every path must start from Kali.
    assert (paths["source"] == ATTACKER).all()


def test_all_paths_reach_target():
    # Every path must end at the database.
    assert (paths["target"] == TARGET).all()


def test_path_ids_are_unique():
    # Duplicate path identifiers are not allowed.
    assert paths["path_id"].is_unique


def test_paths_have_no_cycles():
    # Repeated assets are not allowed within a path.
    for path in paths["asset_path"]:
        assets = path.split(" > ")
        assert len(assets) == len(set(assets))


def test_direct_path_exists():
    # Direct database reachability must be preserved.
    direct = (
        f"{ATTACKER} > {TARGET}"
    )

    assert direct in paths["asset_path"].values


def test_multistage_paths_exist():
    # At least one multi-stage path must exist.
    assert (paths["hop_count"] > 1).any()


def test_path_features_complete():
    # Every generated path must have one feature row.
    assert set(paths["path_id"]) == set(features["path_id"])
    assert len(details) == 11