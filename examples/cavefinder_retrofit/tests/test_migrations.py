"""Unit tests for ``split_cavefinder_user_usage.py``.

This is the only migration script that lives in the cavefinder-side retrofit
kit. Per DESIGN.md §7.3 step 3, the cavefinder side owns the daily-scan
counter split BEFORE identity moves to the IdP, so this script ships with
the cavefinder codebase itself.

The ``migrate_users_to_idp.py`` and ``restore_users_to_cavefinder.py``
scripts are IdP-owned (they read/write the IdP's users.db) and live in
``cave-id/backend/scripts/`` with their own test suite
(``cave-id/backend/tests/test_migrate_users_to_idp.py``,
``test_restore_users_to_cavefinder.py``).

Runs standalone::

    cd examples/cavefinder_retrofit && python -m pytest tests/ -v
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest  # noqa: F401  (imported for conftest side effects if any)

HERE = Path(__file__).resolve().parent
MIGRATIONS_DIR = HERE.parent / "migrations"
sys.path.insert(0, str(MIGRATIONS_DIR))

import split_cavefinder_user_usage  # noqa: E402


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────
def _seed_cavefinder_users_db(path: Path, rows: list[dict]) -> None:
    """Minimal cavefinder-shaped users table matching DESIGN §4.4 plus legacy usage columns."""
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT,
            password_hash TEXT,
            email_verified INTEGER DEFAULT 0,
            verification_code TEXT,
            verification_expires INTEGER,
            display_name TEXT,
            tier TEXT DEFAULT 'free',
            tier_expires_at INTEGER,
            grandfathered INTEGER DEFAULT 0,
            reset_code TEXT,
            reset_expires INTEGER,
            is_admin INTEGER DEFAULT 0,
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            subscription_status TEXT,
            subscription_plan TEXT,
            subscription_ends_at INTEGER,
            daily_scans_date TEXT,
            daily_scans_count INTEGER DEFAULT 0,
            created_at TEXT
        );
        """
    )
    for row in rows:
        cols = ", ".join(row.keys())
        placeholders = ", ".join(["?"] * len(row))
        conn.execute(f"INSERT INTO users ({cols}) VALUES ({placeholders})", tuple(row.values()))
    conn.commit()
    conn.close()


# ──────────────────────────────────────────────────────────────
# split_cavefinder_user_usage.py
# ──────────────────────────────────────────────────────────────
def test_split_usage_dry_run_no_write(tmp_path):
    db = tmp_path / "cf.db"
    _seed_cavefinder_users_db(db, [
        {"id": 1, "email": "a@x.com", "password_hash": "h", "daily_scans_date": "2026-04-01", "daily_scans_count": 5},
        {"id": 2, "email": "b@x.com", "password_hash": "h", "daily_scans_date": None, "daily_scans_count": 0},
    ])
    result = split_cavefinder_user_usage.migrate(str(db), dry_run=True)
    assert result == {"extracted": 1, "written": 0, "dry_run": True}
    with sqlite3.connect(db) as conn:
        # user_usage table should not have been created in dry-run.
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='user_usage'"
        ).fetchone()
        assert exists is None


def test_split_usage_populates_table(tmp_path):
    db = tmp_path / "cf.db"
    _seed_cavefinder_users_db(db, [
        {"id": 1, "email": "a@x.com", "password_hash": "h", "daily_scans_date": "2026-04-01", "daily_scans_count": 5},
        {"id": 2, "email": "b@x.com", "password_hash": "h", "daily_scans_count": 3},
    ])
    result = split_cavefinder_user_usage.migrate(str(db), dry_run=False)
    assert result["written"] == 2
    with sqlite3.connect(db) as conn:
        rows = conn.execute("SELECT user_id, daily_scans_count FROM user_usage ORDER BY user_id").fetchall()
    assert rows == [(1, 5), (2, 3)]


def test_split_usage_is_idempotent(tmp_path):
    db = tmp_path / "cf.db"
    _seed_cavefinder_users_db(db, [{"id": 1, "email": "a@x.com", "password_hash": "h", "daily_scans_count": 5}])
    split_cavefinder_user_usage.migrate(str(db), dry_run=False)
    split_cavefinder_user_usage.migrate(str(db), dry_run=False)  # second run
    with sqlite3.connect(db) as conn:
        n = conn.execute("SELECT COUNT(*) FROM user_usage").fetchone()[0]
    assert n == 1


def test_split_usage_refuses_missing_columns(tmp_path):
    """Preflight: if the users table doesn't have daily_scans_* the script aborts."""
    db = tmp_path / "cf.db"
    conn = sqlite3.connect(db)
    conn.executescript("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);")
    conn.close()
    with pytest.raises(SystemExit):
        split_cavefinder_user_usage.migrate(str(db), dry_run=False)
