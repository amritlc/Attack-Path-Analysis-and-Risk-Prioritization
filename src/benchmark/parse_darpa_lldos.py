from pathlib import Path
import xml.etree.ElementTree as ET
import pandas as pd

RAW = Path("data/raw/external/darpa2000/lldos_1")
OUT = Path("data/processed/benchmarks/darpa_lldos")

OUT.mkdir(parents=True, exist_ok=True)

rows = []

# Each DARPA phase file is parsed.
for file in sorted(RAW.glob("mid-level-phase-*.xml")):
    phase = int(file.stem.split("-")[-1])

    root = ET.parse(file).getroot()

    for message in root.findall("IDMEF-Message"):
        alert = message.find("Alert")

        if alert is None:
            continue

        # Event fields are extracted from the XML.
        source = alert.findtext(
            "Source/Node/Address/address",
            default="",
        )

        target = alert.findtext(
            "Target/Node/Address/address",
            default="",
        )

        service = alert.findtext(
            "Target/Service/name",
            default="",
        )

        analyzer = alert.findtext(
            "Analyzer/name",
            default="",
        )

        rows.append({
            "phase": phase,
            "alert_id": alert.get("alertid", ""),
            "impact": alert.get("impact", ""),
            "date": alert.findtext("Time/date", default=""),
            "time": alert.findtext("Time/time", default=""),
            "session_duration": alert.findtext(
                "Time/sessionduration",
                default="",
            ),
            "analyzer": analyzer,
            "source_ip": source,
            "target_ip": target,
            "service": service,
        })

events = pd.DataFrame(rows)

events.to_csv(
    OUT / "darpa_events.csv",
    index=False,
)

# Phase-level counts are calculated.
summary = (
    events.groupby("phase")
    .agg(
        event_count=("alert_id", "count"),
        unique_sources=("source_ip", "nunique"),
        unique_targets=("target_ip", "nunique"),
        unique_services=("service", "nunique"),
    )
    .reset_index()
)

summary.to_csv(
    OUT / "darpa_phase_summary.csv",
    index=False,
)

print(f"Total events: {len(events)}")
print()
print("Phase summary:")
print(summary.to_string(index=False))