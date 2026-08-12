from pathlib import Path
import pandas as pd

BASE = Path("data/raw/external/cve2attack")

x_train = pd.read_csv(BASE / "X_train.csv")
x_test = pd.read_csv(BASE / "X_test.csv")
y_train = pd.read_csv(BASE / "y_train.csv")
y_test = pd.read_csv(BASE / "y_test.csv")

checks = {}

# Input and label rows must align.
checks["train_rows_match"] = len(x_train) == len(y_train)
checks["test_rows_match"] = len(x_test) == len(y_test)

# The same 31 labels must be used in both sets.
checks["labels_match"] = list(y_train.columns) == list(y_test.columns)
checks["label_count_31"] = y_train.shape[1] == 31

# Labels must contain only binary values.
train_values = set(y_train.stack().unique())
test_values = set(y_test.stack().unique())

checks["train_labels_binary"] = train_values <= {0, 1}
checks["test_labels_binary"] = test_values <= {0, 1}

# CVE descriptions must be available.
checks["train_text_present"] = x_train["Text"].notna().all()
checks["test_text_present"] = x_test["Text"].notna().all()

# Training and testing CVEs should not overlap.
train_cves = set(x_train["Name"])
test_cves = set(x_test["Name"])

checks["no_train_test_overlap"] = train_cves.isdisjoint(test_cves)

for name, passed in checks.items():
    print(f"{name}: {passed}")

print("\nDataset:")
print(f"Training rows: {len(x_train)}")
print(f"Test rows: {len(x_test)}")
print(f"ATT&CK labels: {y_train.shape[1]}")

print("\nTraining label support:")
print(y_train.sum().sort_values(ascending=False).to_string())

if not all(checks.values()):
    raise ValueError("CVE to ATT&CK dataset validation failed.")

print("\nDataset validation passed.")