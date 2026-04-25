"""Migration: extract daily_scans_* columns from users → new user_usage table.

DESIGN.md §7.3 + §8:
    daily_scans_* columns moved to a new local table on cavefinder during
    cutover (non-identity data stays on cavefinder; identity moves to IdP).

Idempotent: safe to re-run. Uses INSERT OR REPLACE so a second run just
overwrites existing rows with the same values from users.db.

Usage::

    python split_cavefinder_user_usage.py --db /opt/cavefinder/users.db
    python split_cavefinder_user_usage.py --db /opt/cavefinder/users.db --dry-run

``--dry-run`` prints the row count + a sample of 5 rows without writing.

Reversibility: the ``users.daily_scans_*`` columns are NOT dropped here.
Rollback via ``restore_users_to_cavefinder.py`` rejoins the columns. The
original columns aren't dropped until step 11 of cutover (§8), well after
we're confident the cascade + usage tracking works.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys


SCHEMA = """
CREATE TABLE IF NOT EXISTS user_usage (
    user_id INTEGER PRIMARY KEY,
    daily_scans_date TEXT,
    daily_scans_count INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_user_usage_date ON user_usage(daily_scans_date);
"""


def migrate(db_path: str, *, dry_run: bool = False) -> dict:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        # Preflight — confirm the source columns exist.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        missing = {"daily_scans_date", "daily_scans_count"} - cols
        if missing:
            raise SystemExit(f"users table is missing expected columns: {sorted(missing)}")

        rows = conn.execute(
            """
            SELECT id AS user_id,
                   daily_scans_date,
                   COALESCE(daily_scans_count, 0) AS daily_scans_count
            FROM users
            WHERE daily_scans_date IS NOT NULL OR daily_scans_count > 0
            """
        ).fetchall()

        if dry_run:
            print(f"[dry-run] would extract {len(rows)} rows into user_usage.")
            for r in rows[:5]:
                print(f"  user_id={r['user_id']} date={r['daily_scans_date']!r} count={r['daily_scans_count']}")
            return {"extracted": len(rows), "written": 0, "dry_run": True}

        conn.executescript(SCHEMA)
        inserted = 0
        with conn:
            for r in rows:
                conn.execute(
                    "INSERT OR REPLACE INTO user_usage (user_id, daily_scans_date, daily_scans_count) "
                    "VALUES (?, ?, ?)",
                    (r["user_id"], r["daily_scans_date"], r["daily_scans_count"]),
                )
                inserted += 1
        print(f"Extracted {inserted} rows into user_usage.")
        return {"extracted": len(rows), "written": inserted, "dry_run": False}
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, help="Path to cavefinder users.db")
    parser.add_argument("--dry-run", action="store_true", help="Print counts without writing")
    args = parser.parse_args(argv)
    migrate(args.db, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
