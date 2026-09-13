import json
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

ENDPOINT = "/api/events/"


def valid_payload(**overrides):
    payload = {
        "event_type": "auth.login.failure",
        "source_ip": "10.10.20.45",
        "metadata": {"username": "admin01", "reason": "invalid_credentials"},
    }
    payload.update(overrides)
    return payload


def post(client, auth, payload, raw=None):
    if raw is not None:
        return client.post(ENDPOINT, data=raw, content_type="application/json", headers=auth)
    return client.post(ENDPOINT, json=payload, headers=auth)


# --- valid ingestion ---------------------------------------------------------


def test_valid_event_is_stored(client, write_auth, user, db):
    response = post(client, write_auth, valid_payload(user_id=user))

    assert response.status_code == 201
    body = response.get_json()
    assert body["id"] > 0
    assert response.headers["Location"] == f"/api/events/{body['id']}"

    row = db.execute("SELECT * FROM events WHERE id = %s", (body["id"],)).fetchone()
    assert row["event_type"] == "auth.login.failure"
    assert row["user_id"] == user
    assert str(row["source_ip"]) == "10.10.20.45"
    assert row["metadata"] == {"username": "admin01", "reason": "invalid_credentials"}
    assert row["received_at"] is not None


def test_optional_fields_default(client, write_auth, event_count, db):
    response = post(client, write_auth, {"event_type": "auth.logout"})

    assert response.status_code == 201
    assert event_count() == 1
    row = db.execute("SELECT * FROM events").fetchone()
    assert row["user_id"] is None
    assert row["source_ip"] is None
    assert row["metadata"] == {}


def test_client_occurred_at_is_preserved_alongside_server_received_at(client, write_auth, db):
    occurred = datetime.now(timezone.utc) - timedelta(hours=3)
    response = post(client, write_auth, valid_payload(occurred_at=occurred.isoformat()))

    assert response.status_code == 201
    row = db.execute("SELECT * FROM events").fetchone()
    assert row["occurred_at"] == occurred
    assert row["received_at"] > row["occurred_at"]


# --- validation --------------------------------------------------------------


def test_missing_required_field_stores_nothing(client, write_auth, event_count):
    response = post(client, write_auth, {"source_ip": "10.0.0.1"})

    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "validation_error"
    assert any(d["field"] == "event_type" for d in response.get_json()["error"]["details"])
    assert event_count() == 0


@pytest.mark.parametrize("bad_ip", ["10.10.20.999", "not-an-ip", "10.0.0.0/24", "", "127.0.0.1; DROP TABLE events"])
def test_invalid_ip_stores_nothing(client, write_auth, event_count, bad_ip):
    response = post(client, write_auth, valid_payload(source_ip=bad_ip))

    assert response.status_code == 400
    assert any(d["field"] == "source_ip" for d in response.get_json()["error"]["details"])
    assert event_count() == 0


def test_unknown_event_type_rejected(client, write_auth, event_count):
    response = post(client, write_auth, valid_payload(event_type="login_failed"))

    assert response.status_code == 400
    assert event_count() == 0


@pytest.mark.parametrize("bad_user_id", ["42", 0, -1, True, 1.5])
def test_invalid_user_id_rejected(client, write_auth, event_count, bad_user_id):
    response = post(client, write_auth, valid_payload(user_id=bad_user_id))

    assert response.status_code == 400
    assert event_count() == 0


def test_nonexistent_user_reference_is_a_safe_client_error(client, write_auth, event_count):
    response = post(client, write_auth, valid_payload(user_id=999_999))

    assert response.status_code == 422
    body = response.get_json()
    assert body["error"]["code"] == "unknown_reference"
    # No driver or database text leaks through.
    assert "violates" not in json.dumps(body).lower()
    assert "psycopg" not in json.dumps(body).lower()
    assert event_count() == 0


@pytest.mark.parametrize("bad_metadata", ["a string", 42, [1, 2, 3], True])
def test_non_object_metadata_rejected(client, write_auth, event_count, bad_metadata):
    response = post(client, write_auth, valid_payload(metadata=bad_metadata))

    assert response.status_code == 400
    assert any(d["field"] == "metadata" for d in response.get_json()["error"]["details"])
    assert event_count() == 0


def test_oversized_metadata_rejected(client, write_auth, event_count):
    response = post(client, write_auth, valid_payload(metadata={"blob": "A" * 9000}))

    assert response.status_code == 400
    assert event_count() == 0


def test_metadata_key_explosion_rejected(client, write_auth, event_count):
    response = post(client, write_auth, valid_payload(metadata={f"k{i}": i for i in range(200)}))

    assert response.status_code == 400
    assert event_count() == 0


def test_deeply_nested_metadata_rejected(client, write_auth, event_count):
    nested = current = {}
    for _ in range(12):
        current["next"] = {}
        current = current["next"]

    response = post(client, write_auth, valid_payload(metadata=nested))

    assert response.status_code == 400
    assert event_count() == 0


@pytest.mark.parametrize(
    "raw",
    [
        '{"event_type": "auth.logout", "metadata": {"x": NaN}}',
        '{"event_type": "auth.logout", "metadata": {"x": Infinity}}',
        '{"event_type": "auth.logout", "metadata": {"x": "\\u0000"}}',
    ],
)
def test_values_postgres_cannot_store_are_rejected(client, write_auth, event_count, raw):
    """NaN, Infinity and NUL survive json.loads but jsonb refuses them."""
    response = post(client, write_auth, None, raw=raw)

    assert response.status_code == 400
    assert event_count() == 0


def test_malformed_json_rejected(client, write_auth, event_count):
    response = post(client, write_auth, None, raw='{"event_type": "auth.logout",,}')

    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "malformed_json"
    assert event_count() == 0


def test_non_object_body_rejected(client, write_auth, event_count):
    response = post(client, write_auth, None, raw="[1, 2, 3]")

    assert response.status_code == 400
    assert event_count() == 0


@pytest.mark.parametrize(
    "bad_timestamp",
    [
        "2026-09-13T10:00:00",
        "not-a-timestamp",
        "1970-01-01T00:00:00+00:00",
        (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(),
    ],
)
def test_invalid_timestamps_rejected(client, write_auth, event_count, bad_timestamp):
    response = post(client, write_auth, valid_payload(occurred_at=bad_timestamp))

    assert response.status_code == 400
    assert event_count() == 0


def test_oversized_body_rejected(client, write_auth, event_count):
    response = post(client, write_auth, None, raw=json.dumps({"event_type": "auth.logout", "metadata": {"x": "A" * 200_000}}))

    assert response.status_code == 413
    assert event_count() == 0


def test_wrong_content_type_rejected(client, write_auth):
    response = client.post(ENDPOINT, data="event_type=auth.logout", content_type="text/plain", headers=write_auth)

    assert response.status_code == 415


# --- privilege boundaries ----------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("severity", "critical"),
        ("risk_score", 100),
        ("threat_type", "data.exfiltration"),
        ("status", "resolved"),
        ("result", "succeeded"),
        ("incident_id", 1),
        ("id", 1),
        ("received_at", "2020-01-01T00:00:00+00:00"),
    ],
)
def test_server_owned_fields_cannot_be_supplied(client, write_auth, event_count, field, value):
    response = post(client, write_auth, valid_payload(**{field: value}))

    assert response.status_code == 400
    assert any(d["field"] == field for d in response.get_json()["error"]["details"])
    assert event_count() == 0


def test_unknown_field_rejected(client, write_auth, event_count):
    response = post(client, write_auth, valid_payload(shell="rm -rf /"))

    assert response.status_code == 400
    assert event_count() == 0


# --- authentication and authorization ----------------------------------------


def test_ingestion_requires_credentials(client, event_count):
    response = client.post(ENDPOINT, json=valid_payload())

    assert response.status_code == 401
    assert event_count() == 0


def test_invalid_credentials_rejected(client, event_count):
    response = post(client, {"Authorization": "Bearer wrong-secret-000000000"}, valid_payload())

    assert response.status_code == 401
    assert event_count() == 0


def test_read_scope_cannot_write(client, read_auth, event_count):
    response = post(client, read_auth, valid_payload())

    assert response.status_code == 403
    assert event_count() == 0


def test_write_scope_cannot_read(client, write_auth):
    assert client.get(ENDPOINT, headers=write_auth).status_code == 403


def test_reading_requires_credentials(client):
    assert client.get(ENDPOINT).status_code == 401


# --- retrieval and pagination ------------------------------------------------


def test_get_returns_stored_events(client, write_auth, read_auth):
    for i in range(3):
        assert post(client, write_auth, valid_payload(metadata={"seq": i})).status_code == 201

    response = client.get(ENDPOINT, headers=read_auth)

    assert response.status_code == 200
    body = response.get_json()
    assert len(body["data"]) == 3
    assert {row["metadata"]["seq"] for row in body["data"]} == {0, 1, 2}


def test_pagination_walks_every_event_exactly_once(client, write_auth, read_auth):
    base = datetime.now(timezone.utc) - timedelta(hours=1)
    for i in range(25):
        payload = valid_payload(metadata={"seq": i}, occurred_at=(base + timedelta(seconds=i)).isoformat())
        assert post(client, write_auth, payload).status_code == 201

    seen = []
    cursor = None
    pages = 0
    while True:
        query = f"{ENDPOINT}?limit=10" + (f"&cursor={cursor}" if cursor else "")
        body = client.get(query, headers=read_auth).get_json()
        seen.extend(row["id"] for row in body["data"])
        pages += 1
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert pages == 3
    assert len(seen) == 25
    assert len(set(seen)) == 25
    assert seen == sorted(seen, reverse=True)


@pytest.mark.parametrize("bad_limit", ["0", "-1", "201", "abc"])
def test_invalid_limit_rejected(client, read_auth, bad_limit):
    assert client.get(f"{ENDPOINT}?limit={bad_limit}", headers=read_auth).status_code == 400


def test_malformed_cursor_rejected(client, read_auth):
    response = client.get(f"{ENDPOINT}?cursor=!!!not-base64!!!", headers=read_auth)

    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "validation_error"


def test_single_event_retrieval(client, write_auth, read_auth):
    event_id = post(client, write_auth, valid_payload()).get_json()["id"]

    response = client.get(f"{ENDPOINT}{event_id}", headers=read_auth)

    assert response.status_code == 200
    assert response.get_json()["id"] == event_id
    assert client.get(f"{ENDPOINT}999999", headers=read_auth).status_code == 404


# --- the API does not weaken the database ------------------------------------


def test_database_still_rejects_what_the_api_filters(db):
    """The API's validation is an extra layer, not a replacement for the schema."""
    with pytest.raises(psycopg.errors.CheckViolation):
        db.execute("INSERT INTO events (event_type, occurred_at, metadata) VALUES ('x', now(), '[1,2]')")

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        db.execute("INSERT INTO events (event_type, user_id, occurred_at) VALUES ('x', 999999, now())")

    with pytest.raises(psycopg.errors.NotNullViolation):
        db.execute("INSERT INTO events (event_type, occurred_at) VALUES ('x', NULL)")


def test_id_is_database_generated(client, write_auth, db):
    first = post(client, write_auth, valid_payload()).get_json()["id"]
    second = post(client, write_auth, valid_payload()).get_json()["id"]

    assert second > first
    columns = db.execute(
        "SELECT is_identity FROM information_schema.columns WHERE table_name='events' AND column_name='id'"
    ).fetchone()
    assert columns["is_identity"] == "YES"
