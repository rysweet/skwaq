#!/usr/bin/env python3
"""Expand CWE knowledge graph from MITRE CWE XML.

Reads the official MITRE CWE XML (cwec_v4.19.1.xml), merges with existing
hand-crafted entries in data/cwe-knowledge-graph.json, and writes the
expanded result back. Preserves detection_signals, fn_insight, and other
enriched fields for existing entries.

Usage:
    python3 scripts/expand_cwe_kg.py /tmp/cwe_data/cwec_v4.19.1.xml
"""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NS = {"cwe": "http://cwe.mitre.org/cwe-7"}
KG_PATH = Path(__file__).parent.parent / "data" / "cwe-knowledge-graph.json"


def parse_mitre_xml(xml_path: str) -> list[dict]:
    """Parse MITRE CWE XML and return list of CWE dicts."""
    tree = ET.parse(xml_path)
    root = tree.getroot()

    entries = []
    for weakness in root.findall(".//cwe:Weaknesses/cwe:Weakness", NS):
        cwe_id = f"CWE-{weakness.get('ID')}"
        name = weakness.get("Name", "")
        status = weakness.get("Status", "")

        # Skip deprecated/obsolete entries
        if status in ("Deprecated", "Obsolete"):
            continue

        desc_elem = weakness.find("cwe:Description", NS)
        description = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""

        # Extract parent CWE from RelatedWeaknesses (ChildOf with Primary ordinal)
        parent_cwe = None
        for rel in weakness.findall(".//cwe:Related_Weaknesses/cwe:Related_Weakness", NS):
            if rel.get("Nature") == "ChildOf" and rel.get("Ordinal") == "Primary":
                parent_cwe = f"CWE-{rel.get('CWE_ID')}"
                break
        # Fallback: any ChildOf relationship
        if parent_cwe is None:
            for rel in weakness.findall(".//cwe:Related_Weaknesses/cwe:Related_Weakness", NS):
                if rel.get("Nature") == "ChildOf":
                    parent_cwe = f"CWE-{rel.get('CWE_ID')}"
                    break

        entries.append({
            "cwe_id": cwe_id,
            "name": name,
            "description": description,
            "parent_cwe": parent_cwe,
            "semantic_class": "",
            "danger_categories": [],
            "detection_signals": [],
            "skwaq_tools": [],
            "fn_insight": "",
        })

    return entries


def load_existing_kg(path: Path) -> dict:
    """Load existing knowledge graph and return CWE dict keyed by cwe_id."""
    with open(path) as f:
        data = json.load(f)
    return {entry["cwe_id"]: entry for entry in data["cwes"]}


def merge_entries(mitre_entries: list[dict], existing: dict) -> list[dict]:
    """Merge MITRE entries with existing hand-crafted data.

    For entries that exist in the current KG, preserve all enriched fields
    (detection_signals, fn_insight, semantic_class, danger_categories, skwaq_tools).
    For new entries, use the MITRE data with empty enriched fields.
    Update parent_cwe from MITRE for all entries (more accurate hierarchy).
    """
    merged = {}

    # Start with all MITRE entries
    for entry in mitre_entries:
        cwe_id = entry["cwe_id"]
        if cwe_id in existing:
            # Preserve enriched fields from existing entry
            old = existing[cwe_id]
            merged[cwe_id] = {
                "cwe_id": cwe_id,
                "name": entry["name"],  # Use MITRE canonical name
                "description": old.get("description") or entry["description"],
                "parent_cwe": entry["parent_cwe"],  # MITRE hierarchy is authoritative
                "semantic_class": old.get("semantic_class", ""),
                "danger_categories": old.get("danger_categories", []),
                "detection_signals": old.get("detection_signals", []),
                "skwaq_tools": old.get("skwaq_tools", []),
                "fn_insight": old.get("fn_insight", ""),
            }
        else:
            merged[cwe_id] = entry

    # Include any existing entries NOT in MITRE (shouldn't happen, but be safe)
    for cwe_id, entry in existing.items():
        if cwe_id not in merged:
            merged[cwe_id] = entry

    # Sort by numeric CWE ID
    result = sorted(merged.values(), key=lambda e: int(e["cwe_id"].split("-")[1]))
    return result


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path-to-cwec-xml>", file=sys.stderr)
        sys.exit(1)

    xml_path = sys.argv[1]
    if not Path(xml_path).exists():
        print(f"XML file not found: {xml_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing MITRE CWE XML: {xml_path}")
    mitre_entries = parse_mitre_xml(xml_path)
    print(f"  Found {len(mitre_entries)} active CWE entries in MITRE XML")

    print(f"Loading existing KG: {KG_PATH}")
    existing = load_existing_kg(KG_PATH)
    print(f"  Found {len(existing)} existing entries")

    merged = merge_entries(mitre_entries, existing)
    preserved = sum(1 for e in merged if e["cwe_id"] in existing)
    new_count = len(merged) - preserved

    print(f"Merged result: {len(merged)} total entries")
    print(f"  Preserved enriched data for {preserved} existing entries")
    print(f"  Added {new_count} new entries from MITRE")
    with_parent = sum(1 for e in merged if e.get("parent_cwe"))
    print(f"  Entries with parent_cwe hierarchy: {with_parent}")

    kg = {
        "version": 2,
        "description": "Skwaq CWE knowledge graph — full MITRE CWE database with enriched entries for benchmark CWEs",
        "cwes": merged,
    }

    with open(KG_PATH, "w") as f:
        json.dump(kg, f, indent=2)
        f.write("\n")

    print(f"Written to {KG_PATH}")


if __name__ == "__main__":
    main()
