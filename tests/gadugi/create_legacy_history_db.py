#!/usr/bin/env python3
"""Seed a legacy skwaq gym history database for outside-in QA scenarios."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path


SCHEMA_WITH_METADATA = """
CREATE TABLE runs (
  id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  suite TEXT NOT NULL,
  skwaq_commit TEXT NOT NULL,
  run_metadata_json TEXT DEFAULT '{}',
  precision REAL DEFAULT 0.0,
  recall REAL DEFAULT 0.0,
  f1 REAL DEFAULT 0.0,
  true_positives INTEGER DEFAULT 0,
  false_positives INTEGER DEFAULT 0,
  false_negatives INTEGER DEFAULT 0,
  true_negatives INTEGER DEFAULT 0
);
"""

SCHEMA_WITHOUT_METADATA = """
CREATE TABLE runs (
  id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  suite TEXT NOT NULL,
  skwaq_commit TEXT NOT NULL,
  precision REAL DEFAULT 0.0,
  recall REAL DEFAULT 0.0,
  f1 REAL DEFAULT 0.0,
  true_positives INTEGER DEFAULT 0,
  false_positives INTEGER DEFAULT 0,
  false_negatives INTEGER DEFAULT 0,
  true_negatives INTEGER DEFAULT 0
);
"""


def main() -> int:
    args = sys.argv[1:]
    omit_metadata_column = False
    if args and args[0] == "--omit-metadata-column":
        omit_metadata_column = True
        args = args[1:]

    if len(args) != 1:
        print(
            "usage: create_legacy_history_db.py [--omit-metadata-column] <xdg-data-home>",
            file=sys.stderr,
        )
        return 2

    xdg_data_home = Path(args[0])
    gym_dir = xdg_data_home / "skwaq" / "gym"
    gym_dir.mkdir(parents=True, exist_ok=True)
    db_path = gym_dir / "results.db"
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    if omit_metadata_column:
        conn.executescript(SCHEMA_WITHOUT_METADATA)
        conn.execute(
            """
            INSERT INTO runs (
              id, started_at, finished_at, suite, skwaq_commit,
              precision, recall, f1, true_positives, false_positives,
              false_negatives, true_negatives
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy-no-column",
                "2026-03-12T00:00:00Z",
                "2026-03-12T00:10:00Z",
                "fixtures",
                "abc12345",
                1.0,
                1.0,
                1.0,
                1,
                0,
                0,
                1,
            ),
        )
    else:
        conn.executescript(SCHEMA_WITH_METADATA)
        conn.executemany(
            """
            INSERT INTO runs (
              id, started_at, finished_at, suite, skwaq_commit, run_metadata_json,
              precision, recall, f1, true_positives, false_positives,
              false_negatives, true_negatives
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "legacy-empty-meta",
                    "2026-03-13T00:00:00Z",
                    "2026-03-13T00:10:00Z",
                    "fixtures",
                    "deadbeef",
                    "{}",
                    1.0,
                    1.0,
                    1.0,
                    1,
                    0,
                    0,
                    1,
                ),
                (
                    "legacy-partial-meta",
                    "2026-03-14T00:00:00Z",
                    "2026-03-14T00:10:00Z",
                    "cyberseceval",
                    "cafebabe",
                    json.dumps({"llm_backend": "copilot", "llm_model": "gpt-4.1"}),
                    0.5,
                    0.4,
                    0.444,
                    2,
                    1,
                    3,
                    0,
                ),
                (
                    "legacy-null-meta",
                    "2026-03-15T00:00:00Z",
                    "2026-03-15T00:10:00Z",
                    "juliet",
                    "feedface",
                    None,
                    0.8,
                    0.7,
                    0.747,
                    8,
                    2,
                    3,
                    1,
                ),
            ],
        )
    conn.commit()
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
