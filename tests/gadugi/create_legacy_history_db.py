#!/usr/bin/env python3
"""Seed a legacy skwaq gym history database for outside-in QA scenarios."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path


SCHEMA = """
CREATE TABLE runs (
  id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  suite TEXT NOT NULL,
  skwaq_commit TEXT NOT NULL,
  run_metadata_json TEXT NOT NULL DEFAULT '{}',
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
    if len(sys.argv) != 2:
        print("usage: create_legacy_history_db.py <xdg-data-home>", file=sys.stderr)
        return 2

    xdg_data_home = Path(sys.argv[1])
    gym_dir = xdg_data_home / "skwaq" / "gym"
    gym_dir.mkdir(parents=True, exist_ok=True)
    db_path = gym_dir / "results.db"

    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
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
        ],
    )
    conn.commit()
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
