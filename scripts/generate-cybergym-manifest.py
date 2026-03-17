#!/usr/bin/env python3
"""Generate CyberGym ground truth manifest from tasks.json.

Downloads tasks.json from HuggingFace and generates a TOML manifest
with CWE inference from vulnerability descriptions. This produces
data/gym/ground_truth/cybergym.toml with all 1,507 cases.

Usage:
    python3 scripts/generate-cybergym-manifest.py [--tasks-json PATH]
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

# CWE inference from vulnerability descriptions.
# Maps keywords/phrases to CWE numbers.
# Ordered by specificity: more specific patterns first so they match before generic ones.
CWE_PATTERNS = [
    # Specific memory safety patterns (match before generic buffer/overflow)
    (r"stack.buffer.overflow|stack.based.buffer", [121]),
    (r"heap.buffer.overflow|heap.based.buffer", [122]),
    (r"out.of.bounds.read|oob.read|read.out.of.bounds|reads?.beyond|read.*past", [125]),
    (r"out.of.bounds.write|oob.write|write.out.of.bounds|writes?.beyond", [787]),
    (r"buffer.overflow|heap.overflow|stack.overflow", [787]),
    (r"use.after.free|uaf|use-after-free|access.*freed|dangling.pointer", [416]),
    (r"double.free|double-free", [415]),
    (r"null.pointer|null.deref|nullptr|null pointer dereference|null.check|dereference.*null", [476]),
    (r"uninitialized|uninitialised|not.initialized|indeterminate.value|uninitialized.memory|msan", [457]),
    (r"free.*not.*heap|invalid.free|free.*stack", [590]),
    (r"type.confusion|type.error|wrong.type|incorrect.*cast|bad.*cast|casts?.*to.*wrong", [843]),
    (r"integer.overflow|integer.underflow|int.overflow|integer.truncation|signed.integer", [190]),
    (r"divide.by.zero|division.by.zero|modulo.by.zero", [369]),
    (r"off.by.one|off-by-one|fence.post", [193]),
    (r"negative.size|negative.length|negative.index|negative.value.*size|size.*negative", [190]),
    (r"shift.*exponent|shift.*amount|undefined.*shift|shift.*negative|shift.*overflow", [758]),
    (r"memory.leak|leak.memory|resource.leak", [401]),
    # Format/injection
    (r"format.string", [134]),
    (r"command.injection|os.command", [78]),
    (r"sql.injection", [89]),
    # Resource/robustness
    (r"infinite.loop|infinite.recursion|uncontrolled.recursion|stack.exhaustion", [835]),
    (r"denial.of.service|resource.exhaustion|excessive|algorithmic.complexity", [400]),
    (r"assertion.*fail|abort.*reachable|reachable.*assertion|assert.*fail", [617]),
    (r"hang|timeout|non.terminating|does.not.terminate", [835]),
    # Code quality
    (r"undefined.behavior|ubsan|undefined behaviour|implementation.defined", [758]),
    # Generic memory (last resort — only match if nothing more specific matched)
    (r"memory.corruption|heap.corruption", [119]),
    (r"out.of.bounds|bounds.check|index.out.of", [119]),
    (r"buffer", [119]),
    (r"overflow", [119]),
    (r"underflow", [191]),
    (r"segfault|segmentation.fault|sigsegv", [119]),
    (r"crash", [119]),
]

# Default CWE when no pattern matches
DEFAULT_CWE = 119  # Generic buffer error — most OSS-Fuzz vulns are memory safety


def infer_cwes(description: str) -> list[int]:
    """Infer CWE numbers from a vulnerability description."""
    desc_lower = description.lower()
    cwes = set()
    for pattern, cwe_list in CWE_PATTERNS:
        if re.search(pattern, desc_lower):
            cwes.update(cwe_list)
    if not cwes:
        cwes.add(DEFAULT_CWE)
    return sorted(cwes)


def generate_manifest(tasks: list[dict]) -> str:
    """Generate TOML manifest from tasks.json entries."""
    lines = [
        "# CyberGym benchmark ground truth manifest.",
        "#",
        "# Source: UC Berkeley CyberGym (https://cybergym.io/)",
        "# Generated from tasks.json (1,507 real-world OSS-Fuzz vulnerabilities)",
        "# CWEs are inferred from vulnerability descriptions.",
        "#",
        "# Phase 1: Detection-only evaluation.",
        "",
        'suite = "cybergym"',
        'version = "1.0"',
        'download_url = "https://huggingface.co/datasets/sunblaze-ucb/cybergym"',
        'download_sha256 = ""',
        "",
    ]

    cwe_counts = Counter()
    neg_count = 0
    for task in tasks:
        task_id = task["task_id"]
        lang = task.get("project_language", "c++")
        desc = task.get("vulnerability_description", "")
        cwes = infer_cwes(desc)
        cwe_counts.update(cwes)

        # Positive case (pre-patch)
        lines.append("[[cases]]")
        lines.append(f'id = "{task_id}"')
        lines.append(f'path = "cases/{task_id}"')
        lines.append(f"expected_cwes = {cwes}")
        lines.append("is_negative = false")
        lines.append(f'language = "{lang}"')
        lines.append("")

        # Negative case (post-patch) — the fix should NOT contain the vuln.
        # Only Level 3 tasks have repo-fix.tar.gz.
        difficulty = task.get("task_difficulty", {})
        level3_files = difficulty.get("level3", [])
        has_fix = any("repo-fix" in f for f in level3_files)
        if has_fix:
            neg_count += 1
            lines.append("[[cases]]")
            lines.append(f'id = "{task_id}-fix"')
            lines.append(f'path = "cases/{task_id}-fix"')
            lines.append(f"expected_cwes = {cwes}")
            lines.append("is_negative = true")
            lines.append(f'language = "{lang}"')
            lines.append("")

    # Summary comment
    lines.insert(7, f"# Total cases: {len(tasks)} positive + {neg_count} negative (post-patch)")
    lines.insert(8, f"# CWE distribution: {dict(cwe_counts.most_common(10))}")

    return "\n".join(lines) + "\n"


def main():
    tasks_path = Path("/tmp/cybergym-tasks.json")
    if len(sys.argv) > 2 and sys.argv[1] == "--tasks-json":
        tasks_path = Path(sys.argv[2])

    if not tasks_path.exists():
        print(f"tasks.json not found at {tasks_path}")
        print("Download: curl -sL https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main/tasks.json -o /tmp/cybergym-tasks.json")
        sys.exit(1)

    with open(tasks_path) as f:
        tasks = json.load(f)

    manifest = generate_manifest(tasks)

    out_path = Path("data/gym/ground_truth/cybergym.toml")
    out_path.write_text(manifest)
    print(f"Generated {out_path} with {len(tasks)} cases")

    # Print CWE distribution
    cwe_counts = Counter()
    for task in tasks:
        cwes = infer_cwes(task.get("vulnerability_description", ""))
        cwe_counts.update(cwes)
    print(f"\nCWE distribution (top 15):")
    for cwe, count in cwe_counts.most_common(15):
        print(f"  CWE-{cwe}: {count} cases")


if __name__ == "__main__":
    main()
