import json
import csv
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime, timezone


def _serialize_chain(chain: Dict[str, Any]) -> Dict[str, Any]:
    """Converts dataclasses, datetimes, and sets into JSON-serializable primitives."""
    serialized = dict(chain)
    serialized["start_time"] = chain["start_time"].isoformat() if chain["start_time"] else None
    serialized["end_time"] = chain["end_time"].isoformat() if chain["end_time"] else None
    serialized["sources_involved"] = sorted(list(chain["sources_involved"]))
    serialized["anomalies"] = sorted(list(chain["anomalies"]))

    serialized_events = []
    for event in chain.get("events", []):
        serialized_events.append({
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "source": event.source,
            "artifact_type": event.artifact_type,
            "path": event.path,
            "user_sid": event.user_sid,
            "hash_val": event.hash_val,
            "details": event.details
        })
    serialized["events"] = serialized_events
    return serialized


def export_json(chains: List[Dict[str, Any]], output_path: str | Path) -> None:
    """Exports correlated execution chains with full nested event telemetry to JSON."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    report_payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_chains_synthesized": len(chains),
        "chains": [_serialize_chain(chain) for chain in chains]
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)


def export_csv(chains: List[Dict[str, Any]], output_path: str | Path) -> None:
    """Exports a flat incident response summary table to CSV for spreadsheet analysis."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "target_file",
        "start_time_utc",
        "end_time_utc",
        "sources_involved",
        "user_sid",
        "hash_val",
        "event_count",
        "anomalies"
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for chain in chains:
            writer.writerow({
                "target_file": chain["target_file"],
                "start_time_utc": chain["start_time"].isoformat() if chain["start_time"] else "",
                "end_time_utc": chain["end_time"].isoformat() if chain["end_time"] else "",
                "sources_involved": "; ".join(sorted(chain["sources_involved"])),
                "user_sid": chain["user_sid"] or "N/A",
                "hash_val": chain["hash_val"] or "N/A",
                "event_count": len(chain.get("events", [])),
                "anomalies": "; ".join(sorted(chain["anomalies"])) if chain["anomalies"] else "Clean"
            })