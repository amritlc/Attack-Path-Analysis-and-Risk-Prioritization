from pathlib import Path
import re
import pandas as pd

SOURCE = Path(
    "data/raw/external/mulval/3host/input.P"
)

OUT = Path(
    "data/processed/benchmarks/mulval_3host"
)

OUT.mkdir(parents=True, exist_ok=True)


def split_arguments(text):
    # Only top-level commas are separated.
    arguments = []
    current = ""
    depth = 0

    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1

        if char == "," and depth == 0:
            arguments.append(current.strip())
            current = ""
        else:
            current += char

    if current:
        arguments.append(current.strip())

    return arguments


text = SOURCE.read_text(encoding="utf-8")

rows = []

# MulVAL facts are extracted.
for line in text.splitlines():
    line = line.strip()

    if not line or line.startswith("/*"):
        continue

    match = re.match(r"(\w+)\((.*)\)\.", line)

    if not match:
        continue

    fact = match.group(1)
    values = split_arguments(match.group(2))

    rows.append({
        "fact": fact,
        "arguments": " | ".join(values),
    })

facts = pd.DataFrame(rows)

facts.to_csv(
    OUT / "mulval_facts.csv",
    index=False,
)

print(f"Facts extracted: {len(facts)}")
print()
print(facts.to_string(index=False))