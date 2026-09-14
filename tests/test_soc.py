"""SOC dashboard backend tests.

Covers the browser session (a transport for the existing scoped credentials,
never a second authentication system) and the read-only aggregate endpoint.
"""

from datetime import datetime, timedelta, timezone

import pytest

from sentinelmesh import config

SUMMARY = "/api/soc/summary/"
LOGIN = "/soc/login"
SESSION = "/soc/session"
EVENTS = "/api/events/"
BASE = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

READ_SECRET = "test-read-secret-0000000"
WRITE_SECRET = "test-write-secret-000000"


def ingest(client, auth, **payload):
    response = client.post(EVENTS, json=payload, headers=auth)
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def multi_stage(client, auth, user_id, ip="203.0.113.44"):
    for i in range(5):
        ingest(
            client,
            auth,
            event_type="auth.login.failure",
            source_ip=ip,
            occurred_at=(BASE + timedelta(seconds=i * 10)).isoformat(),
            metadata={"username": "admin01"},
        )
    ingest(
        client,
        auth,
        event_type="api.request",
        user_id=user_id,
        source_ip=ip,
        occurred_at=(BASE + timedelta(seconds=200)).isoformat(),
        metadata={"method": "GET", "path": "/api/admin/users", "device_fingerprint": "fp-dead-vm"},
    )
    ingest(
        client,
        auth,
        event_type="api.request",
        user_id=user_id,
        source_ip=ip,
        occurred_at=(BASE + timedelta(seconds=300)).isoformat(),
        metadata={
            "path": "/api/search",
            "device_fingerprint": "fp-dead-vm",
            "query": {"q": "' OR 1=1 UNION SELECT username FROM users --"},
        },
    )


@pytest.fixture
def attacker(db, make_user):
    user_id = make_user("t.devries", "viewer")
    db.execute(
        "INSERT INTO devices (user_id, device_fingerprint, trust_score) VALUES (%s, 'fp-dead-vm', 4)", (user_id,)
    )
    return user_id


# --- session -----------------------------------------------------------------


def test_summary_requires_authentication(client):
    assert client.get(SUMMARY).status_code == 401


def test_sign_in_with_a_read_credential_opens_a_session(client):
    response = client.post(LOGIN, json={"credential": READ_SECRET})

    assert response.status_code == 200
    assert response.get_json()["operator"] == "test-analyst"
    assert client.get(SESSION).get_json()["authenticated"] is True
    # The session now authorises the dashboard without any bearer header.
    assert client.get(SUMMARY).status_code == 200


def test_session_cookie_is_httponly_and_samesite_strict(client):
    response = client.post(LOGIN, json={"credential": READ_SECRET})

    cookie = response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    # The credential itself is never echoed back into the cookie or body.
    assert READ_SECRET not in cookie
    assert READ_SECRET not in response.get_data(as_text=True)


def test_credential_without_read_scope_is_refused(client):
    """A write-only ingest credential must not open a dashboard session."""
    response = client.post(LOGIN, json={"credential": WRITE_SECRET})

    assert response.status_code == 401
    assert client.get(SESSION).get_json()["authenticated"] is False


def test_wrong_and_missing_credentials_are_refused_identically(client):
    wrong = client.post(LOGIN, json={"credential": "nope-nope-nope-nope"})
    no_scope = client.post(LOGIN, json={"credential": WRITE_SECRET})

    assert wrong.status_code == no_scope.status_code == 401
    assert wrong.get_json()["error"]["message"] == no_scope.get_json()["error"]["message"]


@pytest.mark.parametrize("payload", [{}, {"credential": ""}, {"credential": 42}, {"other": "x"}])
def test_malformed_sign_in_is_rejected(client, payload):
    assert client.post(LOGIN, json=payload).status_code == 400


def test_sign_out_ends_the_session(client):
    client.post(LOGIN, json={"credential": READ_SECRET})
    client.post("/soc/logout")

    assert client.get(SESSION).get_json()["authenticated"] is False
    assert client.get(SUMMARY).status_code == 401


def test_session_does_not_grant_scopes_the_credential_lacks(client, db, make_user):
    """A read session cannot trigger containment."""
    client.post(LOGIN, json={"credential": READ_SECRET})

    assert client.post("/api/incidents/1/respond/").status_code in (403, 404)
    assert client.post(EVENTS, json={"event_type": "auth.logout"}).status_code == 403


def test_bearer_authentication_still_works(client, read_auth):
    assert client.get(SUMMARY, headers=read_auth).status_code == 200


# --- summary -----------------------------------------------------------------


def test_summary_is_empty_on_a_clean_system(client, read_auth):
    body = client.get(SUMMARY, headers=read_auth).get_json()

    assert body["incidents"] == {"active": 0, "critical": 0, "high": 0, "other": 0, "total": 0}
    assert body["containment"] == {"contained_subjects": 0, "isolated_devices": 0, "blocked_sources": 0}
    assert body["recent_threats"] == []
    assert body["recent_responses"] == []


def test_summary_counts_come_from_database_state(client, write_auth, read_auth, db, attacker):
    multi_stage(client, write_auth, attacker)

    body = client.get(SUMMARY, headers=read_auth).get_json()
    expected_critical = db.execute(
        "SELECT count(*) AS n FROM incidents WHERE status IN ('open','investigating') AND risk_score >= 80"
    ).fetchone()["n"]

    assert body["incidents"]["critical"] == expected_critical == 1
    assert body["incidents"]["active"] == 1
    assert body["containment"] == {"contained_subjects": 1, "isolated_devices": 1, "blocked_sources": 1}
    assert len(body["recent_threats"]) == 3
    assert {r["action"] for r in body["recent_responses"]} >= {"contain_subject", "block_source"}


def test_summary_separates_high_from_critical(client, write_auth, read_auth, attacker):
    # A brute-force campaign alone is HIGH, not CRITICAL.
    for i in range(5):
        ingest(
            client,
            write_auth,
            event_type="auth.login.failure",
            source_ip="198.51.100.9",
            occurred_at=(BASE + timedelta(seconds=i * 10)).isoformat(),
            metadata={"username": "bob"},
        )

    body = client.get(SUMMARY, headers=read_auth).get_json()
    assert body["incidents"]["critical"] == 0
    assert body["incidents"]["high"] == 1


def test_summary_exposes_no_credentials(client, write_auth, read_auth, attacker):
    multi_stage(client, write_auth, attacker)

    rendered = client.get(SUMMARY, headers=read_auth).get_data(as_text=True)

    for secret in [READ_SECRET, WRITE_SECRET, "test-decide-secret", "test-respond-secret"]:
        assert secret not in rendered


# --- incident detail for the dashboard ---------------------------------------


def test_incident_detail_serves_the_whole_investigation_in_one_request(
    client, write_auth, read_auth, decide_auth, db, attacker
):
    multi_stage(client, write_auth, attacker)
    incident_id = db.execute("SELECT id FROM incidents").fetchone()["id"]
    client.post(
        "/api/access/decision/",
        json={"resource": "/api/internal", "subject_user_id": attacker, "source_ip": "203.0.113.44"},
        headers=decide_auth,
    )

    body = client.get(f"/api/incidents/{incident_id}", headers=read_auth).get_json()

    assert body["threats"] and body["timeline"] and body["responses"]
    assert body["zero_trust"], "the dashboard must not have to ask a second endpoint"
    assert body["containment"]["subjects"][0]["contained"] is True
    assert body["containment"]["devices"][0]["isolated"] is True
    assert body["containment"]["sources"][0]["blocked"] is True
    assert body["risk_factors"]["factors"]
    assert body["correlation_factors"]["attack_stages"]


def test_incident_threats_carry_their_risk_factors(client, write_auth, read_auth, db, attacker):
    multi_stage(client, write_auth, attacker)
    incident_id = db.execute("SELECT id FROM incidents").fetchone()["id"]

    body = client.get(f"/api/incidents/{incident_id}", headers=read_auth).get_json()

    for threat in body["threats"]:
        assert threat["risk_factors"]["factors"], "Phase 3 factors must reach the dashboard"
        assert threat["risk_factors"]["model_version"] == config.RISK_MODEL_VERSION


def test_dashboard_routes_never_shadow_the_api(client):
    """The SPA catch-all must not swallow an unknown API path."""
    assert client.get("/api/does-not-exist").status_code == 404
    assert client.get("/soc/does-not-exist").status_code == 404


# --- incident ordering for the SOC queue -------------------------------------


def test_incidents_can_be_ordered_worst_first(client, write_auth, read_auth, attacker):
    """A SOC queue must surface the most dangerous incident first."""
    multi_stage(client, write_auth, attacker)
    for i in range(5):
        ingest(
            client,
            write_auth,
            event_type="auth.login.failure",
            source_ip="198.51.100.9",
            occurred_at=(BASE + timedelta(seconds=400 + i * 10)).isoformat(),
            metadata={"username": "bob"},
        )

    by_risk = client.get("/api/incidents/?sort=risk", headers=read_auth).get_json()["data"]
    scores = [i["risk_score"] for i in by_risk]

    assert scores == sorted(scores, reverse=True)
    assert by_risk[0]["severity"] == "critical"


def test_risk_ordering_pages_without_repeating_or_skipping(client, write_auth, read_auth, attacker):
    multi_stage(client, write_auth, attacker)
    for i in range(5):
        ingest(
            client,
            write_auth,
            event_type="auth.login.failure",
            source_ip="198.51.100.9",
            occurred_at=(BASE + timedelta(seconds=400 + i * 10)).isoformat(),
            metadata={"username": "bob"},
        )

    seen, cursor = [], None
    for _ in range(5):
        query = "/api/incidents/?sort=risk&limit=1" + (f"&cursor={cursor}" if cursor else "")
        page = client.get(query, headers=read_auth).get_json()
        seen.extend(i["id"] for i in page["data"])
        cursor = page["next_cursor"]
        if cursor is None:
            break

    assert len(seen) == len(set(seen)) == 2


def test_recent_ordering_remains_the_default(client, write_auth, read_auth, attacker):
    multi_stage(client, write_auth, attacker)

    ids = [i["id"] for i in client.get("/api/incidents/", headers=read_auth).get_json()["data"]]
    assert ids == sorted(ids, reverse=True)


@pytest.mark.parametrize("query", ["sort=sideways", "sort=risk&cursor=not-a-cursor"])
def test_invalid_sort_and_cursor_are_rejected(client, read_auth, query):
    assert client.get(f"/api/incidents/?{query}", headers=read_auth).status_code == 400
