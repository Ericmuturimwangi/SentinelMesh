import os
import subprocess
import sys
from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

TEST_DB = os.environ.get("SENTINELMESH_TEST_DB", "sentinelmesh_test")
ADMIN_DSN = os.environ.get("SENTINELMESH_ADMIN_DSN", "postgresql:///postgres")
TEST_DSN = f"postgresql:///{TEST_DB}"

WRITE_SECRET = "test-write-secret-000000"
READ_SECRET = "test-read-secret-0000000"
DECIDE_SECRET = "test-decide-secret-00000"

TABLES = "events, threats, incidents, responses, devices, users, access_decisions"


@pytest.fixture(scope="session", autouse=True)
def database():
    with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE)')
        conn.execute(f'CREATE DATABASE "{TEST_DB}"')

    subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "migrate.py"), "up"],
        env={**os.environ, "DATABASE_URL": TEST_DSN},
        check=True,
        capture_output=True,
    )
    yield TEST_DSN


@pytest.fixture(scope="session")
def app(database):
    os.environ["DATABASE_URL"] = database
    os.environ["SENTINELMESH_API_KEYS"] = (
        f"test-agent:write:{WRITE_SECRET},test-analyst:read:{READ_SECRET},"
        f"test-gateway:decide:{DECIDE_SECRET}"
    )
    from sentinelmesh.app import create_app

    application = create_app({"TESTING": True})
    yield application
    application.extensions["db_pool"].close()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db():
    """A connection outside the app's pool, for asserting what really landed."""
    with psycopg.connect(TEST_DSN, row_factory=dict_row, autocommit=True) as conn:
        yield conn


@pytest.fixture(autouse=True)
def clean_tables(database, db):
    db.execute(f"TRUNCATE {TABLES} RESTART IDENTITY CASCADE")


@pytest.fixture
def user(db):
    row = db.execute(
        "INSERT INTO users (username, role) VALUES ('a.okafor', 'analyst') RETURNING id"
    ).fetchone()
    return row["id"]


@pytest.fixture
def make_user(db):
    def _make(username: str, role: str) -> int:
        return db.execute(
            "INSERT INTO users (username, role) VALUES (%s, %s) RETURNING id", (username, role)
        ).fetchone()["id"]

    return _make


@pytest.fixture
def rerun_detection():
    """Re-run the engine over an already-stored event, outside Flask.

    The dispatcher only needs a psycopg connection, so this also demonstrates
    that detection does not depend on the request layer.
    """
    from sentinelmesh.detection import run_detection

    def _run(event_id: int):
        with psycopg.connect(TEST_DSN, row_factory=dict_row) as conn:
            event = conn.execute("SELECT * FROM events WHERE id = %s", (event_id,)).fetchone()
            detections = run_detection(conn, event)
            conn.commit()
            return detections

    return _run


@pytest.fixture
def write_auth():
    return {"Authorization": f"Bearer {WRITE_SECRET}"}


@pytest.fixture
def read_auth():
    return {"Authorization": f"Bearer {READ_SECRET}"}


@pytest.fixture
def decide_auth():
    return {"Authorization": f"Bearer {DECIDE_SECRET}"}


@pytest.fixture
def event_count(db):
    def count():
        return db.execute("SELECT count(*) AS n FROM events").fetchone()["n"]

    return count
