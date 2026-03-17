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
CWE_PATTERNS = [
    # Memory safety
    (r"buffer.overflow|heap.overflow|stack.overflow|out.of.bounds.write", [787]),
    (r"out.of.bounds.read|oob.read|read.out.of.bounds", [125]),
    (r"use.after.free|uaf|use-after-free", [416]),
    (r"null.pointer|null.deref|nullptr|null pointer dereference", [476]),
    (r"double.free", [415]),
    (r"memory.leak|leak.memory", [401]),
    (r"integer.overflow|integer.underflow|int.overflow", [190]),
    (r"type.confusion|type.error|wrong.type|cast", [843]),
    (r"uninitialized|uninitialised|not.initialized", [457]),
    (r"free.*not.*heap|invalid.free|free.*stack", [590]),
    (r"divide.by.zero|division.by.zero", [369]),
    (r"off.by.one", [193]),
    (r"stack.buffer", [121]),
    (r"heap.buffer", [122]),
    # Format/injection
    (r"format.string", [134]),
    (r"command.injection|os.command", [78]),
    (r"sql.injection", [89]),
    # Resource/robustness
    (r"infinite.loop|infinite.recursion|uncontrolled.recursion", [835]),
    (r"denial.of.service|resource.exhaustion|excessive", [400]),
    (r"assertion|abort|assert.*fail", [617]),
    # Code quality
    (r"undefined.behavior|ubsan|undefined behaviour", [758]),
    # Generic memory
    (r"memory.corruption|heap.corruption", [119]),
    (r"buffer", [119]),
    (r"overflow", [119]),
    (r"underflow", [191]),
    (r"segfault|segmentation.fault|sigsegv|crash", [119]),
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

    # Summary comment
    lines.insert(7, f"# Total cases: {len(tasks)}")
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
