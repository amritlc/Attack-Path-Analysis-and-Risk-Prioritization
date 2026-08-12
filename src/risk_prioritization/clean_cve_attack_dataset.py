from pathlib import Path
import json
import pandas as pd

RAW = Path("data/raw/external/cve2attack")
OUT = Path("data/processed/cve2attack")

OUT.mkdir(parents=True, exist_ok=True)

# Original datasets are loaded.
x_train = pd.read_csv(RAW / "X_train.csv")
y_train = pd.read_csv(RAW / "y_train.csv")
x_test = pd.read_csv(RAW / "X_test.csv")
y_test = pd.read_csv(RAW / "y_test.csv")

original_train_rows = len(x_train)
original_test_rows = len(x_test)

# CVEs shared between training and testing are identified.
test_cves = set(x_test["Name"])

overlap_mask = x_train["Name"].isin(test_cves)

overlap_rows = int(overlap_mask.sum())
overlap_cves = sorted(
    set(x_train.loc[overlap_mask, "Name"])
)

# Test CVEs are removed only from the training set.
x_train = x_train[~overlap_mask].copy()
y_train = y_train[~overlap_mask].copy()

# Indexes are reset so features and labels remain aligned.
x_train = x_train.reset_index(drop=True)
y_train = y_train.reset_index(drop=True)

# Duplicate CVEs remaining in training are identified.
duplicate_mask = x_train["Name"].duplicated(
    keep=False
)

duplicate_cves = sorted(
    x_train.loc[duplicate_mask, "Name"].unique()
)

rows_before_merge = len(x_train)

labels = list(y_train.columns)

# Features and labels are joined for duplicate consolidation.
combined = pd.concat(
    [x_train, y_train],
    axis=1,
)

clean_rows = []

# One row is retained for each CVE.
for cve, group in combined.groupby(
    "Name",
    sort=False,
):
    row = {
        "Name": cve,
        "Text": group.iloc[0]["Text"],
    }

    # Existing positive labels are preserved using logical OR.
    for label in labels:
        row[label] = int(group[label].max())

    clean_rows.append(row)

clean = pd.DataFrame(clean_rows)

x_clean = clean[
    ["Name", "Text"]
].copy()

y_clean = clean[
    labels
].copy()

duplicate_rows_removed = (
    rows_before_merge - len(x_clean)
)

# Clean training data is saved.
x_clean.to_csv(
    OUT / "X_train_clean.csv",
    index=False,
)

y_clean.to_csv(
    OUT / "y_train_clean.csv",
    index=False,
)

# The supplied test partition is preserved unchanged.
x_test.to_csv(
    OUT / "X_test.csv",
    index=False,
)

y_test.to_csv(
    OUT / "y_test.csv",
    index=False,
)

# A reproducible cleaning summary is saved.
summary = {
    "original_training_rows": original_train_rows,
    "original_test_rows": original_test_rows,
    "overlapping_cves": overlap_cves,
    "removed_test_overlap_rows": overlap_rows,
    "duplicate_training_cves": duplicate_cves,
    "duplicate_rows_removed": duplicate_rows_removed,
    "final_training_rows": len(x_clean),
    "final_unique_training_cves": x_clean["Name"].nunique(),
    "final_test_rows": len(x_test),
    "test_modified": False,
}

with open(
    OUT / "cleaning_summary.json",
    "w",
    encoding="utf-8",
) as file:
    json.dump(
        summary,
        file,
        indent=2,
    )

print("Dataset cleaning complete.")
print()
print(json.dumps(summary, indent=2))