#!/usr/bin/env python3
"""Generate full-size benchmark manifests for all suites.

Reads ground truth data from source datasets and generates TOML manifests
with all available test cases for each benchmark suite.
"""

import csv
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SKWAQ_ROOT = Path(__file__).parent.parent
GT_DIR = SKWAQ_ROOT / "data" / "gym" / "ground_truth"
GYM_CACHE = Path.home() / ".local" / "share" / "skwaq" / "gym" / "cache"
GYM_DOWNLOADS = Path("/tmp/gym-downloads")


def generate_cgc_manifest():
    """Generate CGC manifest from cb-multios challenge READMEs."""
    cgc_dir = GYM_DOWNLOADS / "cb-multios"
    if not cgc_dir.exists():
        print("  CGC data not found, skipping")
        return

    challenges_dir = cgc_dir / "challenges"
    cases = []

    for challenge in sorted(challenges_dir.iterdir()):
        if not challenge.is_dir():
            continue

        src_dir = challenge / "src"
        if not src_dir.is_dir():
            continue

        # Find CWE annotations from README
        readme = challenge / "README.md"
        cwes = []
        if readme.exists():
            text = readme.read_text(errors="replace")
            # Look for CWE references
            cwe_matches = re.findall(r"CWE[- ]?(\d+)", text, re.IGNORECASE)
            cwes = sorted(set(int(c) for c in cwe_matches))

        if not cwes:
            # Default: most CGC challenges involve memory corruption
            cwes = [119]

        # Find main source file
        main_file = None
        for candidate in ["main.c", "service.c", "main.cc"]:
            if (src_dir / candidate).exists():
                main_file = candidate
                break
        if main_file is None:
            c_files = list(src_dir.glob("*.c"))
            if c_files:
                main_file = c_files[0].name
            else:
                continue

        cases.append({
            "id": challenge.name,
            "path": f"challenges/{challenge.name}/src/{main_file}",
            "expected_cwes": cwes,
            "is_negative": False,
            "language": "c",
        })

    # Add negative (patched) entries: ~25% of positives.
    # CGC challenges use #ifdef PATCHED_1 code paths for fixed versions.
    # The patched version of the same source file has no vulnerabilities.
    positive_cases = [c for c in cases if not c["is_negative"]]
    step = max(1, len(positive_cases) // 50)
    for c in positive_cases[::step][:51]:
        cases.append({
            "id": c["id"] + "_patched",
            "path": c["path"],
            "expected_cwes": [],
            "is_negative": True,
            "language": "c",
        })

    negatives = sum(1 for c in cases if c["is_negative"])
    positives = len(cases) - negatives
    # Write manifest
    write_toml(GT_DIR / "cgc.toml", "cgc", "cb-multios", cases)
    print(f"  CGC: {len(cases)} cases ({positives} positive, {negatives} negative)")


def generate_juliet_manifest():
    """Generate Juliet manifest from testcase directory structure.

    Path structure: testcases/CWE{NNN}_{name}/s{NN}/{file}.c
    Paths must be relative to the C/ directory (the cache root).
    """
    juliet_c_dir = GYM_DOWNLOADS / "juliet" / "C"
    juliet_dir = juliet_c_dir / "testcases"
    if not juliet_dir.exists():
        print("  Juliet data not found, skipping")
        return

    cases = []
    # Map directory CWE names to CWE numbers
    cwe_dir_pattern = re.compile(r"CWE(\d+)")

    for cwe_dir in sorted(juliet_dir.iterdir()):
        if not cwe_dir.is_dir():
            continue

        match = cwe_dir_pattern.match(cwe_dir.name)
        if not match:
            continue

        cwe_id = int(match.group(1))

        # Walk through subdirectories to find .c test files
        for root, _, files in os.walk(cwe_dir):
            for fname in sorted(files):
                if not fname.endswith(".c"):
                    continue
                # Skip helper/support files
                if fname.startswith("_") or "helper" in fname.lower():
                    continue

                fpath = Path(root) / fname
                # Path must be relative to the C/ dir (cache root)
                rel_path = fpath.relative_to(juliet_c_dir)

                # Determine if this is a "good" (negative) or "bad" (positive) case
                is_negative = "_good" in fname.lower()

                case_id = fpath.stem
                expected_cwes = [] if is_negative else [cwe_id]

                cases.append({
                    "id": case_id,
                    "path": str(rel_path),
                    "expected_cwes": expected_cwes,
                    "is_negative": is_negative,
                    "language": "c",
                })

    # Also add testcasesupport/ files as negatives (safe helper code)
    support_dir = juliet_c_dir / "testcasesupport"
    if support_dir.is_dir():
        for fname in sorted(support_dir.iterdir()):
            if fname.suffix in (".c", ".h"):
                rel_path = fname.relative_to(juliet_c_dir)
                cases.append({
                    "id": f"juliet_support_{fname.stem}",
                    "path": str(rel_path),
                    "expected_cwes": [],
                    "is_negative": True,
                    "language": "c",
                })

    negatives = sum(1 for c in cases if c["is_negative"])
    positives = len(cases) - negatives
    write_toml(GT_DIR / "juliet.toml", "juliet", "1.3", cases)
    print(f"  Juliet: {len(cases)} cases ({positives} positive, {negatives} negative)")


def generate_owasp_manifest():
    """Generate OWASP Benchmark manifest from expectedresults CSV."""
    owasp_dir = GYM_DOWNLOADS / "BenchmarkJava"
    csv_path = owasp_dir / "expectedresults-1.2.csv"
    if not csv_path.exists():
        print("  OWASP data not found, skipping")
        return

    # Map OWASP test categories to CWEs
    category_to_cwe = {
        "cmdi": 78,
        "crypto": 327,
        "hash": 328,
        "ldapi": 90,
        "pathtraver": 22,
        "securecookie": 614,
        "sqli": 89,
        "trustbound": 501,
        "weakrand": 330,
        "xpathi": 643,
        "xss": 79,
    }

    cases = []
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            test_name = row.get("# test name", "").strip()
            category = row.get(" category", "").strip()
            is_vuln = row.get(" real vulnerability", "").strip().lower() == "true"
            cwe_raw = row.get(" CWE", "").strip()

            if not test_name:
                continue

            # Parse CWE
            cwe_id = int(cwe_raw) if cwe_raw.isdigit() else category_to_cwe.get(category, 0)
            if cwe_id == 0:
                continue

            # Find the Java source file
            # OWASP Benchmark test names map to src/main/java/org/owasp/benchmark/testcode/
            java_path = f"src/main/java/org/owasp/benchmark/testcode/{test_name}.java"

            cases.append({
                "id": test_name,
                "path": java_path,
                "expected_cwes": [cwe_id] if is_vuln else [],
                "is_negative": not is_vuln,
                "language": "java",
            })

    write_toml(GT_DIR / "owasp.toml", "owasp", "1.2", cases)
    print(f"  OWASP: {len(cases)} cases ({sum(1 for c in cases if not c['is_negative'])} positive, {sum(1 for c in cases if c['is_negative'])} negative)")


def generate_cyberseceval_manifest():
    """Generate CyberSecEval manifest from instruct.json (C + Python cases)."""
    instruct_path = GYM_DOWNLOADS / "PurpleLlama" / "CybersecurityBenchmarks" / "datasets" / "instruct" / "instruct.json"
    if not instruct_path.exists():
        print("  CyberSecEval data not found, skipping")
        return

    with open(instruct_path) as f:
        data = json.load(f)

    # CWE string to number mapping
    cwe_pattern = re.compile(r"CWE[- ]?(\d+)", re.IGNORECASE)

    cases = []
    case_dir = GYM_CACHE / "cyberseceval" / "cases"
    case_dir.mkdir(parents=True, exist_ok=True)

    for i, entry in enumerate(data):
        lang = entry.get("language", "").lower()
        if lang not in ("c", "python"):
            continue

        # Extract CWEs from the entry
        cwe_str = entry.get("cwe_identifier", "") or entry.get("cwe", "")
        cwe_matches = cwe_pattern.findall(str(cwe_str))
        cwes = sorted(set(int(c) for c in cwe_matches))

        if not cwes:
            continue

        # Determine file extension
        ext = ".c" if lang == "c" else ".py"
        case_id = f"cyberseceval_{i}_{lang}"
        filename = f"{case_id}{ext}"

        # Write the actual vulnerable source code to the cache directory.
        # origin_code contains the real vulnerable code; test_case_prompt is just
        # a natural language description that pattern detectors can't analyze.
        code = entry.get("origin_code", "")
        if not code.strip():
            # Fallback: skip entries without actual code
            continue

        (case_dir / filename).write_text(code)

        cases.append({
            "id": case_id,
            "path": f"cases/{filename}",
            "expected_cwes": cwes,
            "is_negative": False,
            "language": lang,
        })

    # Add entries without CWE identifiers as negatives (safe code)
    neg_idx = len(cases)
    for i, entry in enumerate(data):
        lang = entry.get("language", "").lower()
        if lang not in ("c", "python"):
            continue

        cwe_str = entry.get("cwe_identifier", "") or entry.get("cwe", "")
        cwe_matches = cwe_pattern.findall(str(cwe_str))
        if cwe_matches:
            continue  # Has CWEs, already handled above

        code = entry.get("origin_code", "")
        if not code.strip():
            continue

        ext = ".c" if lang == "c" else ".py"
        case_id = f"cyberseceval_{neg_idx}_{lang}_safe"
        filename = f"{case_id}{ext}"
        (case_dir / filename).write_text(code)
        neg_idx += 1

        cases.append({
            "id": case_id,
            "path": f"cases/{filename}",
            "expected_cwes": [],
            "is_negative": True,
            "language": lang,
        })

    negatives = sum(1 for c in cases if c["is_negative"])
    positives = len(cases) - negatives
    write_toml(GT_DIR / "cyberseceval.toml", "cyberseceval", "1.0", cases)
    print(f"  CyberSecEval: {len(cases)} cases ({positives} positive, {negatives} negative)")


def write_toml(path: Path, suite: str, version: str, cases: list):
    """Write a TOML manifest file."""
    lines = [
        f'suite = "{suite}"',
        f'version = "{version}"',
        'download_url = ""',
        'download_sha256 = ""',
        "",
    ]

    for case in cases:
        lines.append("[[cases]]")
        lines.append(f'id = "{case["id"]}"')
        lines.append(f'path = "{case["path"]}"')
        cwes_str = ", ".join(str(c) for c in case["expected_cwes"])
        lines.append(f"expected_cwes = [{cwes_str}]")
        lines.append(f'is_negative = {"true" if case["is_negative"] else "false"}')
        lines.append(f'language = "{case["language"]}"')
        lines.append("")

    path.write_text("\n".join(lines))


def main():
    print("Generating full benchmark manifests...")

    generate_cgc_manifest()
    generate_juliet_manifest()
    generate_owasp_manifest()
    generate_cyberseceval_manifest()

    # Show before/after with positive/negative breakdown
    print("\nManifest case counts:")
    for toml_file in sorted(GT_DIR.glob("*.toml")):
        lines = toml_file.read_text().splitlines()
        total = sum(1 for line in lines if line == "[[cases]]")
        negatives = sum(1 for line in lines if line == "is_negative = true")
        positives = total - negatives
        print(f"  {toml_file.name}: {total} cases ({positives} positive, {negatives} negative)")


if __name__ == "__main__":
    main()
