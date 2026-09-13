from datetime import datetime, timedelta, timezone

import pytest

from sentinelmesh import config

EVENTS = "/api/events/"
THREATS = "/api/threats/"

BASE = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


def ingest(client, auth, **payload):
    response = client.post(EVENTS, json=payload, headers=auth)
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def failed_login(client, auth, ip="10.10.20.45", offset=0, **extra):
    metadata = {"username": "admin01", "reason": "invalid_credentials"}
    metadata.update(extra.pop("metadata", {}))
    return ingest(
        client,
        auth,
        event_type="auth.login.failure",
        source_ip=ip,
        occurred_at=(BASE + timedelta(seconds=offset)).isoformat(),
        metadata=metadata,
        **extra,
    )


def api_request(client, auth, path="/api/reports", method="GET", offset=0, **extra):
    metadata = {"method": method, "path": path}
    metadata.update(extra.pop("metadata", {}))
    return ingest(
        client,
        auth,
        event_type="api.request",
        source_ip="10.10.20.45",
        occurred_at=(BASE + timedelta(seconds=offset)).isoformat(),
        metadata=metadata,
        **extra,
    )


def threats_for(db, event_id):
    return db.execute("SELECT * FROM threats WHERE event_id = %s", (event_id,)).fetchall()


# --- rule 1: brute force -----------------------------------------------------


def test_four_failures_do_not_detect(client, write_auth, db):
    for i in range(4):
        failed_login(client, write_auth, offset=i * 10)

    assert db.execute("SELECT count(*) AS n FROM threats").fetchone()["n"] == 0


def test_five_failures_within_window_detect(client, write_auth, db):
    bodies = [failed_login(client, write_auth, offset=i * 10) for i in range(5)]

    assert bodies[-1]["detections"][0]["threat_type"] == config.THREAT_BRUTE_FORCE
    rows = threats_for(db, bodies[-1]["id"])
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "brute_force.v1"
    assert rows[0]["severity"] == "high"
    assert float(rows[0]["confidence"]) == config.BRUTE_FORCE_CONFIDENCE

    # Only the triggering event carries a threat.
    assert db.execute("SELECT count(*) AS n FROM threats").fetchone()["n"] == 1


def test_brute_force_evidence_is_explainable(client, write_auth, db):
    bodies = [failed_login(client, write_auth, offset=i * 10) for i in range(5)]
    evidence = threats_for(db, bodies[-1]["id"])[0]["evidence"]

    assert evidence["reason"] == "5 failed login attempts from 10.10.20.45 within 120 seconds"
    assert evidence["source_ip"] == "10.10.20.45"
    assert evidence["failure_count"] == 5
    assert evidence["window_seconds"] == config.BRUTE_FORCE_WINDOW_SECONDS
    assert evidence["contributing_event_ids"] == sorted(b["id"] for b in bodies)


def test_five_failures_outside_window_do_not_detect(client, write_auth, db):
    # 60s apart, so no 120s window ever holds five.
    for i in range(5):
        failed_login(client, write_auth, offset=i * 60)

    assert db.execute("SELECT count(*) AS n FROM threats").fetchone()["n"] == 0


def test_five_failures_from_different_ips_do_not_detect(client, write_auth, db):
    for i in range(5):
        failed_login(client, write_auth, ip=f"10.10.20.{i + 1}", offset=i * 10)

    assert db.execute("SELECT count(*) AS n FROM threats").fetchone()["n"] == 0


def test_successful_logins_do_not_count_toward_brute_force(client, write_auth, db):
    for i in range(4):
        failed_login(client, write_auth, offset=i * 10)
    ingest(
        client,
        write_auth,
        event_type="auth.login.success",
        source_ip="10.10.20.45",
        occurred_at=(BASE + timedelta(seconds=50)).isoformat(),
    )

    assert db.execute("SELECT count(*) AS n FROM threats").fetchone()["n"] == 0


def test_threshold_comes_from_configuration():
    assert config.BRUTE_FORCE_THRESHOLD == 5
    assert config.BRUTE_FORCE_WINDOW_SECONDS == 120


# --- rule 2: SQL injection ---------------------------------------------------


def test_normal_request_is_not_flagged(client, write_auth, db):
    body = api_request(client, write_auth, path="/api/reports", metadata={"query": {"page": "2", "sort": "name"}})

    assert body["detections"] == []
    assert threats_for(db, body["id"]) == []


@pytest.mark.parametrize(
    "benign",
    [
        "salt and pepper",
        "red or blue",
        "name=value&page=2",
        "order by date",
        "comment: the union meeting",
        "user@example.com",
        "-- a dash comment in prose",
        "5 > 3 and 2 < 4",
        "C:\\Users\\admin",
    ],
)
def test_benign_strings_are_not_false_positives(client, write_auth, db, benign):
    body = api_request(client, write_auth, metadata={"query": {"search": benign}})

    assert body["detections"] == []
    assert threats_for(db, body["id"]) == []


@pytest.mark.parametrize(
    "payload,expected_pattern",
    [
        ("' OR 1=1 --", "tautology"),
        ("admin' OR 'a'='a", "tautology"),
        ("1 UNION SELECT username, password FROM users", "union_select"),
        ("x'; DROP TABLE events; --", "stacked_query"),
        ("admin'--", "comment_terminator"),
        ("1 AND pg_sleep(10)", "time_based"),
    ],
)
def test_injection_payloads_are_detected(client, write_auth, db, payload, expected_pattern):
    body = api_request(client, write_auth, metadata={"query": {"search": payload}})

    assert body["detections"][0]["threat_type"] == config.THREAT_SQL_INJECTION
    row = threats_for(db, body["id"])[0]
    assert row["severity"] == "critical"
    assert row["rule_id"] == "sql_injection.v1"
    assert expected_pattern in row["evidence"]["matched_patterns"]
    assert row["evidence"]["fields"] == ["query.search"]


def test_confidence_rises_with_independent_indicators(client, write_auth, db):
    single = api_request(client, write_auth, offset=1, metadata={"query": {"q": "admin'--"}})
    multiple = api_request(
        client,
        write_auth,
        offset=2,
        metadata={"query": {"q": "' OR 1=1 UNION SELECT a FROM b; DROP TABLE x; --"}},
    )

    assert multiple["detections"][0]["confidence"] > single["detections"][0]["confidence"]
    assert multiple["detections"][0]["confidence"] <= config.SQLI_CONFIDENCE_MAX


def test_injection_payload_is_never_executed(client, write_auth, db):
    before = db.execute("SELECT count(*) AS n FROM events").fetchone()["n"]

    body = api_request(client, write_auth, metadata={"query": {"q": "'; DROP TABLE events; TRUNCATE users; --"}})

    # The table still exists and nothing was destroyed: the payload was matched
    # against a regex, never sent to the database as code.
    after = db.execute("SELECT count(*) AS n FROM events").fetchone()["n"]
    assert after == before + 1
    assert db.execute("SELECT to_regclass('public.events') AS t").fetchone()["t"] == "events"
    assert db.execute("SELECT to_regclass('public.users') AS t").fetchone()["t"] == "users"
    assert threats_for(db, body["id"])[0]["threat_type"] == config.THREAT_SQL_INJECTION


def test_secrets_are_not_copied_into_evidence(client, write_auth, db):
    body = api_request(
        client,
        write_auth,
        metadata={
            "query": {"search": "' OR 1=1 --"},
            "password": "hunter2' OR 1=1 --",
            "api_key": "sk-live-abcdef' OR 1=1 --",
            "session_token": "tok' OR 1=1 --",
        },
    )

    evidence = threats_for(db, body["id"])[0]["evidence"]
    serialised = str(evidence)
    assert "hunter2" not in serialised
    assert "sk-live-abcdef" not in serialised
    assert "tok'" not in serialised
    assert evidence["fields"] == ["query.search"]


def test_evidence_snippets_are_bounded(client, write_auth, db):
    # A match far longer than the snippet cap, but within the 1024-character
    # limit Phase 1 validation already imposes on metadata strings.
    payload = "OR " + "a" * 300 + "=" + "a" * 300
    body = api_request(client, write_auth, metadata={"query": {"q": payload}})

    indicators = threats_for(db, body["id"])[0]["evidence"]["indicators"]
    assert indicators
    for indicator in indicators:
        assert len(indicator["snippet"]) <= config.SQLI_SNIPPET_CHARS


def test_injection_in_login_credentials_is_detected(client, write_auth, db):
    body = ingest(
        client,
        write_auth,
        event_type="auth.login.failure",
        source_ip="10.10.20.45",
        metadata={"username": "' OR 1=1 --"},
    )

    assert threats_for(db, body["id"])[0]["threat_type"] == config.THREAT_SQL_INJECTION


# --- rule 3: unauthorized privileged access ----------------------------------


def test_admin_accessing_privileged_resource_is_not_flagged(client, write_auth, db, make_user):
    admin = make_user("m.acheampong", "admin")

    body = api_request(client, write_auth, path="/api/admin/users", user_id=admin)

    assert body["detections"] == []
    assert threats_for(db, body["id"]) == []


def test_unprivileged_user_accessing_privileged_resource_is_flagged(client, write_auth, db, make_user):
    viewer = make_user("t.devries", "viewer")

    body = api_request(client, write_auth, path="/api/admin/users", user_id=viewer)

    assert body["detections"][0]["threat_type"] == config.THREAT_PRIVILEGED_ACCESS
    row = threats_for(db, body["id"])[0]
    assert row["rule_id"] == "privileged_access.v1"
    assert row["evidence"]["actor_role"] == "viewer"
    assert row["evidence"]["path"] == "/api/admin/users"
    assert row["evidence"]["matched_prefix"] == "/api/admin"
    assert "viewer" in row["evidence"]["reason"]


def test_unauthenticated_privileged_access_is_flagged(client, write_auth, db):
    body = api_request(client, write_auth, path="/api/internal/config")

    row = threats_for(db, body["id"])[0]
    assert row["threat_type"] == config.THREAT_PRIVILEGED_ACCESS
    assert row["evidence"]["actor_role"] is None
    assert "unauthenticated" in row["evidence"]["reason"]


def test_role_is_read_from_the_database_not_from_metadata(client, write_auth, db, make_user):
    """An attacker claiming to be an admin in metadata must not suppress the rule."""
    viewer = make_user("t.devries", "viewer")

    body = api_request(
        client, write_auth, path="/api/admin/users", user_id=viewer, metadata={"role": "admin"}
    )

    assert threats_for(db, body["id"])[0]["evidence"]["actor_role"] == "viewer"


def test_non_privileged_path_is_not_flagged(client, write_auth, db, make_user):
    viewer = make_user("t.devries", "viewer")

    body = api_request(client, write_auth, path="/api/reports", user_id=viewer)

    assert threats_for(db, body["id"]) == []


def test_path_prefix_is_not_bypassed_by_suffix(client, write_auth, db, make_user):
    viewer = make_user("t.devries", "viewer")

    body = api_request(client, write_auth, path="/api/admin/users/../../public", user_id=viewer)

    assert threats_for(db, body["id"])[0]["threat_type"] == config.THREAT_PRIVILEGED_ACCESS


# --- persistence and idempotency ---------------------------------------------


def test_event_to_threat_persistence(client, write_auth, db):
    bodies = [failed_login(client, write_auth, offset=i * 10) for i in range(5)]
    triggering = bodies[-1]["id"]

    row = db.execute(
        "SELECT t.*, e.event_type FROM threats t JOIN events e ON e.id = t.event_id WHERE t.event_id = %s",
        (triggering,),
    ).fetchone()

    assert row["event_type"] == "auth.login.failure"
    assert row["detected_at"] is not None
    assert row["incident_id"] is None


def test_rerunning_detection_does_not_duplicate(client, write_auth, db, rerun_detection):
    bodies = [failed_login(client, write_auth, offset=i * 10) for i in range(5)]
    triggering = bodies[-1]["id"]

    first = threats_for(db, triggering)[0]
    for _ in range(3):
        rerun_detection(triggering)

    rows = threats_for(db, triggering)
    assert len(rows) == 1
    assert rows[0]["id"] == first["id"]
    assert rows[0]["threat_type"] == first["threat_type"]
    assert rows[0]["evidence"] == first["evidence"]


def test_rerun_is_deterministic(client, write_auth, rerun_detection):
    bodies = [failed_login(client, write_auth, offset=i * 10) for i in range(5)]

    runs = [rerun_detection(bodies[-1]["id"]) for _ in range(3)]

    assert all(len(r) == 1 for r in runs)
    assert len({(d[0]["threat_type"], d[0]["confidence"], d[0]["reason"]) for d in runs}) == 1


def test_multiple_rules_can_fire_on_one_event(client, write_auth, db, make_user):
    viewer = make_user("t.devries", "viewer")

    body = api_request(
        client, write_auth, path="/api/admin/users", user_id=viewer, metadata={"query": {"q": "' OR 1=1 --"}}
    )

    types = {row["threat_type"] for row in threats_for(db, body["id"])}
    assert types == {config.THREAT_SQL_INJECTION, config.THREAT_PRIVILEGED_ACCESS}


def test_unique_constraint_backs_idempotency(db):
    """The (event_id, threat_type) constraint is what prevents duplicates."""
    constraint = db.execute(
        "SELECT conname FROM pg_constraint WHERE conrelid = 'threats'::regclass AND contype = 'u'"
    ).fetchone()
    assert constraint["conname"] == "threats_event_type_key"


# --- untrusted input ---------------------------------------------------------


def test_unexpected_event_type_runs_no_rules(client, write_auth, db):
    body = ingest(client, write_auth, event_type="process.exec", metadata={"cmd": "' OR 1=1 --"})

    # process.exec is outside every rule's scope, so nothing fires.
    assert threats_for(db, body["id"]) == []


def test_missing_metadata_fields_do_not_break_rules(client, write_auth, db):
    for payload in [
        {"event_type": "api.request"},
        {"event_type": "api.request", "metadata": {}},
        {"event_type": "api.request", "metadata": {"path": None}},
        {"event_type": "api.request", "metadata": {"method": "GET"}},
        {"event_type": "auth.login.failure"},
    ]:
        response = client.post(EVENTS, json=payload, headers=write_auth)
        assert response.status_code == 201


def test_non_string_path_is_ignored(client, write_auth, db, make_user):
    viewer = make_user("t.devries", "viewer")
    body = ingest(
        client,
        write_auth,
        event_type="api.request",
        user_id=viewer,
        metadata={"path": {"nested": "/api/admin"}, "method": ["GET"]},
    )

    assert threats_for(db, body["id"]) == []


def test_extremely_long_values_are_handled(client, write_auth, db):
    # The 8KB metadata cap keeps rule input bounded.
    long_but_allowed = "A" * 1000
    body = api_request(client, write_auth, metadata={"query": {"q": long_but_allowed}})

    assert threats_for(db, body["id"]) == []


def test_unicode_input_is_handled(client, write_auth, db):
    body = api_request(
        client,
        write_auth,
        metadata={"query": {"q": "Ωμέγα 日本語 🔐 café", "note": "Ｕ' OR 1=1 --"}},
    )

    rows = threats_for(db, body["id"])
    assert len(rows) == 1
    assert rows[0]["evidence"]["fields"] == ["query.note"]


def test_deeply_nested_metadata_is_walked_safely(client, write_auth, db):
    nested = {"a": {"b": {"c": {"d": "' OR 1=1 --"}}}}
    body = api_request(client, write_auth, metadata=nested)

    assert threats_for(db, body["id"])[0]["threat_type"] == config.THREAT_SQL_INJECTION


def test_repeated_identical_events_each_get_their_own_threat(client, write_auth, db):
    """Distinct events are distinct subjects; the constraint scopes to one event."""
    bodies = [api_request(client, write_auth, offset=i, metadata={"query": {"q": "' OR 1=1 --"}}) for i in range(3)]

    assert len({b["id"] for b in bodies}) == 3
    for body in bodies:
        assert len(threats_for(db, body["id"])) == 1
    assert db.execute("SELECT count(*) AS n FROM threats").fetchone()["n"] == 3


def test_injection_in_event_fields_does_not_reach_sql(client, write_auth, db):
    """Rule queries are parameterised, including the inet comparison."""
    body = failed_login(client, write_auth, ip="10.10.20.45", metadata={"username": "'; DELETE FROM threats; --"})

    assert db.execute("SELECT to_regclass('public.threats') AS t").fetchone()["t"] == "threats"
    assert threats_for(db, body["id"])[0]["threat_type"] == config.THREAT_SQL_INJECTION


# --- threats read API --------------------------------------------------------


def test_threats_endpoint_requires_read_scope(client, write_auth):
    assert client.get(THREATS).status_code == 401
    assert client.get(THREATS, headers=write_auth).status_code == 403


def test_threats_endpoint_returns_detections(client, write_auth, read_auth):
    bodies = [failed_login(client, write_auth, offset=i * 10) for i in range(5)]

    response = client.get(THREATS, headers=read_auth)

    assert response.status_code == 200
    data = response.get_json()["data"]
    assert len(data) == 1
    assert data[0]["event_id"] == bodies[-1]["id"]
    assert data[0]["rule_id"] == "brute_force.v1"
    assert data[0]["evidence"]["reason"].startswith("5 failed login attempts")


def test_threats_can_be_filtered_by_event(client, write_auth, read_auth):
    api_request(client, write_auth, offset=1, metadata={"query": {"q": "' OR 1=1 --"}})
    second = api_request(client, write_auth, offset=2, metadata={"query": {"q": "1 UNION SELECT a FROM b"}})

    data = client.get(f"{THREATS}?event_id={second['id']}", headers=read_auth).get_json()["data"]

    assert len(data) == 1
    assert data[0]["event_id"] == second["id"]


def test_threats_pagination(client, write_auth, read_auth):
    for i in range(5):
        api_request(client, write_auth, offset=i, metadata={"query": {"q": "' OR 1=1 --"}})

    first = client.get(f"{THREATS}?limit=2", headers=read_auth).get_json()
    assert len(first["data"]) == 2
    assert first["next_cursor"] is not None

    second = client.get(f"{THREATS}?limit=2&cursor={first['next_cursor']}", headers=read_auth).get_json()
    assert len(second["data"]) == 2
    assert {row["id"] for row in first["data"]}.isdisjoint({row["id"] for row in second["data"]})


def test_single_threat_retrieval(client, write_auth, read_auth, db):
    body = api_request(client, write_auth, metadata={"query": {"q": "' OR 1=1 --"}})
    threat_id = threats_for(db, body["id"])[0]["id"]

    assert client.get(f"{THREATS}{threat_id}", headers=read_auth).status_code == 200
    assert client.get(f"{THREATS}999999", headers=read_auth).status_code == 404


def test_clients_still_cannot_submit_threat_fields(client, write_auth, db):
    response = client.post(
        EVENTS,
        json={"event_type": "api.request", "threat_type": "injection.sql", "confidence": 1.0},
        headers=write_auth,
    )

    assert response.status_code == 400
    assert db.execute("SELECT count(*) AS n FROM threats").fetchone()["n"] == 0
