#!/usr/bin/env python3
"""Apply the SQL files in migrations/ in filename order.

    DATABASE_URL=postgresql://... python migrate.py [up|status]
"""

import hashlib
import os
import sys
from pathlib import Path

import psycopg

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

LEDGER = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename   text PRIMARY KEY,
    checksum   text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)
"""


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else "up"
    if command not in ("up", "status"):
        print(f"unknown command: {command}", file=sys.stderr)
        return 2

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        print("DATABASE_URL is not set", file=sys.stderr)
        return 2

    with psycopg.connect(dsn) as conn:
        conn.execute(LEDGER)
        conn.commit()
        applied = dict(conn.execute("SELECT filename, checksum FROM schema_migrations").fetchall())

        for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()

            if path.name in applied:
                if applied[path.name] != digest:
                    print(f"{path.name} was edited after it was applied", file=sys.stderr)
                    return 1
                print(f"applied  {path.name}")
                continue

            if command == "status":
                print(f"pending  {path.name}")
                continue

            with conn.transaction():
                conn.execute(path.read_text())
                conn.execute(
                    "INSERT INTO schema_migrations (filename, checksum) VALUES (%s, %s)",
                    (path.name, digest),
                )
            print(f"applied  {path.name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
