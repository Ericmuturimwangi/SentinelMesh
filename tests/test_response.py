"""Automated response engine tests.

Pure policy first (no database), then execution, idempotency, concurrency and
containment enforcement against real PostgreSQL state.
"""

from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from sentinelmesh import config
from sentinelmesh.response import (
    ResponseContext,
    evaluate_response,
    load_response_context,
    respond_to_incident,
)

EVENTS = "/api/events/"
INCIDENTS = "/api/incidents/"
RESPONSES = "/api/responses/"
DECIDE = "/api/access/decision/"
BASE = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

ALERT = config.ACTION_ALERT
STEP_UP = config.ACTION_REQUIRE_STEP_UP
CONTAIN = config.ACTION_CONTAIN_SUBJECT
BLOCK = config.ACTION_BLOCK_SOURCE
ISOLATE = config.ACTION_ISOLATE_DEVICE


def ctx(**overrides) -> ResponseContext:
    base = {
        "incident_id": 1,
        "incident_risk": 0,
        "incident_classification": "credential_attack",
        "incident_status": "open",
        "highest_threat_risk": 0,
        "threat_types": ("credential.bruteforce",),
        "threat_count": 1,
        "affected_user_ids": (2,),
        "affected_usernames": ("t.devries",),
        "source_ips": ("203.0.113.44",),
        "device_ids": (5,),
        "device_fingerprints": ("fp-dead-vm",),
    }
    base.update(overrides)
    return ResponseContext(**base)


# --- pure policy -------------------------------------------------------------


def test_low_risk_produces_no_actions():
    """No containment and no alert noise for benign activity."""
    plan = evaluate_response(ctx(incident_risk=10, highest_threat_risk=10))

    assert plan.actions == ()
    assert plan.policy == config.RESPONSE_POLICY_LOW
    assert plan.severity == "low"


def test_medium_risk_alerts_only():
    plan = evaluate_response(ctx(incident_risk=45, highest_threat_risk=45))

    assert plan.actions == (ALERT,)
    assert plan.policy == config.RESPONSE_POLICY_MEDIUM


def test_high_incident_alerts_and_requires_step_up():
    plan = evaluate_response(ctx(incident_risk=64, highest_threat_risk=64))

    assert plan.actions == (ALERT, STEP_UP)
    assert plan.policy == config.RESPONSE_POLICY_HIGH_INCIDENT
    assert CONTAIN not in plan.actions, "high risk alone must not contain a principal"


def test_high_threat_without_an_incident_does_not_contain():
    plan = evaluate_response(ctx(incident_risk=0, highest_threat_risk=72))

    assert plan.actions == (ALERT, STEP_UP)
    assert plan.policy == config.RESPONSE_POLICY_HIGH_THREAT


def test_critical_incident_contains_everything_in_scope():
    plan = evaluate_response(ctx(incident_risk=100, highest_threat_risk=94))

    assert plan.actions == (ALERT, CONTAIN, BLOCK, ISOLATE)
    assert plan.policy == config.RESPONSE_POLICY_CRITICAL_INCIDENT
    assert plan.severity == "critical"


def test_critical_threat_contains_but_does_not_isolate_a_device():
    """A lone critical threat is not yet a campaign."""
    plan = evaluate_response(ctx(incident_risk=0, highest_threat_risk=94))

    assert plan.actions == (ALERT, CONTAIN, BLOCK)
    assert ISOLATE not in plan.actions
    assert plan.policy == config.RESPONSE_POLICY_CRITICAL_THREAT


def test_high_does_not_trigger_the_critical_policy():
    for risk in range(config.ZT_HIGH_RISK, config.ZT_CRITICAL_RISK):
        plan = evaluate_response(ctx(incident_risk=risk))
        assert CONTAIN not in plan.actions
        assert BLOCK not in plan.actions


def test_incident_outranks_an_equal_threat_tier():
    campaign = evaluate_response(ctx(incident_risk=100, highest_threat_risk=64))
    lone = evaluate_response(ctx(incident_risk=0, highest_threat_risk=64))

    assert len(campaign.actions) > len(lone.actions)


def test_actions_are_limited_to_entities_in_scope():
    plan = evaluate_response(
        ctx(incident_risk=100, affected_user_ids=(), source_ips=(), device_ids=())
    )

    assert plan.actions == (ALERT,)


def test_plan_is_deterministic():
    context = ctx(incident_risk=100, highest_threat_risk=94)

    plans = {evaluate_response(context).to_dict()["policy"] for _ in range(25)}
    actions = {evaluate_response(context).actions for _ in range(25)}

    assert len(plans) == 1 and len(actions) == 1


def test_plan_is_explainable():
    plan = evaluate_response(ctx(incident_risk=100))
    payload = plan.to_dict()

    assert payload["model_version"] == config.RESPONSE_MODEL_VERSION
    assert payload["reason"] and payload["policy"]
    assert payload["evidence"]["source_ips"] == ["203.0.113.44"]
    assert payload["evidence"]["affected_users"] == ["t.devries"]


def test_policy_performs_no_writes(db):
    """The pure function takes no connection, so it cannot mutate anything."""
    import inspect

    assert "conn" not in inspect.signature(evaluate_response).parameters


# --- integration scaffolding -------------------------------------------------


def ingest(client, auth, **payload):
    response = client.post(EVENTS, json=payload, headers=auth)
    assert response.status_code == 201, response.get_json()
    return response.get_json()


@pytest.fixture
def attacker(db, make_user):
    user_id = make_user("t.devries", "viewer")
    db.execute(
        "INSERT INTO devices (user_id, device_fingerprint, trust_score) VALUES (%s, 'fp-dead-vm', 4)", (user_id,)
    )
    return user_id


def brute_force(client, auth, ip="203.0.113.44", count=5, start=0):
    for i in range(count):
        ingest(
            client,
            auth,
            event_type="auth.login.failure",
            source_ip=ip,
            occurred_at=(BASE + timedelta(seconds=start + i * 10)).isoformat(),
            metadata={"username": "admin01", "attempt": i},
        )


def multi_stage(client, auth, user_id, ip="203.0.113.44"):
    brute_force(client, auth, ip)
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


def actions_for(db, incident_id=None):
    if incident_id is None:
        rows = db.execute("SELECT * FROM responses ORDER BY id").fetchall()
    else:
        rows = db.execute("SELECT * FROM responses WHERE incident_id = %s ORDER BY id", (incident_id,)).fetchall()
    return {r["action"]: r for r in rows}


# --- integration: the pipeline drives the response ---------------------------


def test_multi_stage_attack_triggers_full_containment(client, write_auth, db, attacker):
    multi_stage(client, write_auth, attacker)

    incident = db.execute("SELECT * FROM incidents").fetchone()
    assert int(incident["risk_score"]) >= config.ZT_CRITICAL_RISK

    applied = actions_for(db, incident["id"])
    # require_step_up is retained from when the campaign was only HIGH: the
    # audit trail records the escalation rather than rewriting it.
    assert set(applied) == {ALERT, STEP_UP, CONTAIN, BLOCK, ISOLATE}
    assert all(r["result"] == config.RESULT_EXECUTED for r in applied.values())
    for action in (CONTAIN, BLOCK, ISOLATE):
        assert applied[action]["policy"] == config.RESPONSE_POLICY_CRITICAL_INCIDENT
    assert applied[STEP_UP]["policy"] == config.RESPONSE_POLICY_HIGH_INCIDENT


def test_containment_state_is_written_to_authoritative_records(client, write_auth, db, attacker):
    multi_stage(client, write_auth, attacker)

    assert db.execute("SELECT contained FROM users WHERE id = %s", (attacker,)).fetchone()["contained"] is True
    assert db.execute("SELECT isolated FROM devices WHERE user_id = %s", (attacker,)).fetchone()["isolated"] is True
    assert db.execute(
        "SELECT count(*) AS n FROM blocked_sources WHERE source_ip = '203.0.113.44'"
    ).fetchone()["n"] == 1


def test_low_risk_event_produces_no_response(client, write_auth, db, attacker):
    ingest(client, write_auth, event_type="auth.login.success", source_ip="10.0.0.1", user_id=attacker)

    assert db.execute("SELECT count(*) AS n FROM responses").fetchone()["n"] == 0
    assert db.execute("SELECT contained FROM users WHERE id = %s", (attacker,)).fetchone()["contained"] is False


def test_brute_force_alone_does_not_contain_the_principal(client, write_auth, db, attacker):
    """A single credential campaign is high, not critical: escalate, don't contain."""
    brute_force(client, write_auth)

    incident = db.execute("SELECT * FROM incidents").fetchone()
    applied = actions_for(db, incident["id"])

    assert int(incident["risk_score"]) < config.ZT_CRITICAL_RISK
    assert set(applied) == {ALERT, STEP_UP}
    assert db.execute("SELECT count(*) AS n FROM blocked_sources").fetchone()["n"] == 0


def test_response_is_reported_on_ingestion(client, write_auth, attacker):
    brute_force(client, write_auth, count=4)
    body = ingest(
        client,
        write_auth,
        event_type="auth.login.failure",
        source_ip="203.0.113.44",
        occurred_at=(BASE + timedelta(seconds=40)).isoformat(),
        metadata={"username": "admin01"},
    )

    response = body["detections"][0]["response"]
    assert response["policy"] == config.RESPONSE_POLICY_HIGH_INCIDENT
    assert [a["action"] for a in response["actions"]] == [ALERT, STEP_UP]
    assert response["failed"] == []


# --- integration: idempotency and concurrency --------------------------------


def test_repeated_processing_does_not_duplicate_containment(client, write_auth, db, attacker):
    multi_stage(client, write_auth, attacker)
    incident_id = db.execute("SELECT id FROM incidents").fetchone()["id"]
    before = db.execute("SELECT count(*) AS n FROM responses").fetchone()["n"]

    with psycopg.connect(
        db.info.dsn, row_factory=psycopg.rows.dict_row
    ) as conn:  # fresh connection, as a second worker would use
        for _ in range(4):
            outcome = respond_to_incident(conn, incident_id, actor="test")
            conn.commit()
            assert all(a["result"] == config.RESULT_ALREADY_APPLIED for a in outcome["actions"])

    assert db.execute("SELECT count(*) AS n FROM responses").fetchone()["n"] == before
    assert db.execute("SELECT count(*) AS n FROM blocked_sources").fetchone()["n"] == 1


def test_unique_constraint_forbids_duplicate_actions(db):
    incident_id = db.execute(
        "INSERT INTO incidents (title, severity, risk_score, correlation_key, classification, last_activity_at)"
        " VALUES ('t', 'high', 90, 'ip:1.2.3.4', 'multi_stage_attack', now()) RETURNING id"
    ).fetchone()["id"]
    db.execute("INSERT INTO responses (incident_id, action, result) VALUES (%s, 'alert', 'succeeded')", (incident_id,))

    with pytest.raises(psycopg.errors.UniqueViolation):
        db.execute(
            "INSERT INTO responses (incident_id, action, result) VALUES (%s, 'alert', 'succeeded')", (incident_id,)
        )


def test_concurrent_responders_produce_one_action_each(client, write_auth, db, attacker):
    import threading

    multi_stage(client, write_auth, attacker)
    incident_id = db.execute("SELECT id FROM incidents").fetchone()["id"]
    db.execute("DELETE FROM responses")
    db.execute("UPDATE users SET contained = false")
    db.execute("UPDATE devices SET isolated = false")
    db.execute("DELETE FROM blocked_sources")

    barrier = threading.Barrier(4)
    errors = []

    def worker():
        try:
            with psycopg.connect(db.info.dsn, row_factory=psycopg.rows.dict_row) as conn:
                barrier.wait(timeout=10)
                respond_to_incident(conn, incident_id, actor="worker")
                conn.commit()
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=25)

    assert not errors, errors
    rows = db.execute("SELECT action, count(*) AS n FROM responses GROUP BY action").fetchall()
    assert {r["action"] for r in rows} == {ALERT, CONTAIN, BLOCK, ISOLATE}
    assert all(r["n"] == 1 for r in rows), "one logical action per action type"
    assert db.execute("SELECT count(*) AS n FROM blocked_sources").fetchone()["n"] == 1


# --- integration: containment feeds back into zero trust ---------------------


def test_blocked_source_is_visible_to_later_decisions(client, write_auth, decide_auth, db, attacker):
    multi_stage(client, write_auth, attacker)
    db.execute("UPDATE users SET contained = false")  # isolate the source signal

    body = client.post(
        DECIDE,
        json={"resource": "/api/public/status", "subject_user_id": attacker, "source_ip": "203.0.113.44"},
        headers=decide_auth,
    ).get_json()

    assert body["decision"] == config.DENY


def test_contained_subject_is_denied_even_after_the_incident_is_triaged(
    client, write_auth, decide_auth, db, attacker
):
    """Containment is real enforcement, not a flag nobody reads."""
    multi_stage(client, write_auth, attacker)
    # Analyst triages the incident away and the detections age out of the
    # active window; containment alone must still hold the line.
    db.execute("UPDATE incidents SET status = 'resolved'")
    db.execute("UPDATE threats SET detected_at = now() - interval '2 days'")
    db.execute("DELETE FROM blocked_sources")

    body = client.post(
        DECIDE, json={"resource": "/api/public/status", "subject_user_id": attacker}, headers=decide_auth
    ).get_json()

    assert body["decision"] == config.DENY
    assert body["policy"] == "subject_contained"


def test_isolated_device_is_denied(client, write_auth, decide_auth, db, attacker):
    multi_stage(client, write_auth, attacker)
    db.execute("UPDATE incidents SET status = 'resolved'")
    db.execute("UPDATE threats SET detected_at = now() - interval '2 days'")
    db.execute("UPDATE users SET contained = false")
    db.execute("DELETE FROM blocked_sources")

    body = client.post(
        DECIDE,
        json={
            "resource": "/api/public/status",
            "subject_user_id": attacker,
            "device_fingerprint": "fp-dead-vm",
        },
        headers=decide_auth,
    ).get_json()

    assert body["decision"] == config.DENY
    assert body["policy"] == "device_isolated"


def test_uninvolved_user_is_not_contained(client, write_auth, decide_auth, db, attacker, make_user):
    bystander = make_user("r.mensah", "responder")
    db.execute(
        "INSERT INTO devices (user_id, device_fingerprint, trust_score) VALUES (%s, 'fp-clean', 95)", (bystander,)
    )
    multi_stage(client, write_auth, attacker)

    assert db.execute("SELECT contained FROM users WHERE id = %s", (bystander,)).fetchone()["contained"] is False
    assert db.execute("SELECT isolated FROM devices WHERE user_id = %s", (bystander,)).fetchone()["isolated"] is False

    body = client.post(
        DECIDE,
        json={"resource": "/api/search", "subject_user_id": bystander, "device_fingerprint": "fp-clean"},
        headers=decide_auth,
    ).get_json()
    assert body["decision"] == config.ALLOW


def test_step_up_directive_is_enforced_by_zero_trust(client, write_auth, decide_auth, db, attacker):
    """require_step_up records the directive; Phase 5 is what enforces it."""
    brute_force(client, write_auth)
    assert STEP_UP in actions_for(db)

    body = client.post(
        DECIDE,
        json={"resource": "/api/search", "subject_user_id": attacker, "source_ip": "203.0.113.44"},
        headers=decide_auth,
    ).get_json()

    assert body["decision"] == config.STEP_UP


# --- integration: failure handling -------------------------------------------


def test_one_failing_action_does_not_mark_the_rest_successful(client, write_auth, db, attacker, monkeypatch):
    multi_stage(client, write_auth, attacker)
    incident_id = db.execute("SELECT id FROM incidents").fetchone()["id"]
    db.execute("DELETE FROM responses")
    db.execute("UPDATE users SET contained = false")
    db.execute("UPDATE devices SET isolated = false")
    db.execute("DELETE FROM blocked_sources")

    from sentinelmesh import response as response_module

    def broken(conn, context):
        raise RuntimeError("simulated isolation failure")

    monkeypatch.setitem(response_module.EXECUTORS, ISOLATE, broken)

    with psycopg.connect(db.info.dsn, row_factory=psycopg.rows.dict_row) as conn:
        outcome = respond_to_incident(conn, incident_id, actor="test")
        conn.commit()

    results = {a["action"]: a["result"] for a in outcome["actions"]}
    assert results[ISOLATE] == config.RESULT_FAILED
    assert results[CONTAIN] == config.RESULT_EXECUTED
    assert results[BLOCK] == config.RESULT_EXECUTED
    assert outcome["failed"] == [ISOLATE]

    stored = actions_for(db, incident_id)
    assert stored[ISOLATE]["result"] == config.RESULT_FAILED
    assert stored[CONTAIN]["result"] == config.RESULT_EXECUTED


def test_incident_remains_visible_after_containment(client, write_auth, db, attacker):
    """Containment must not quietly close the incident: that would fail open."""
    multi_stage(client, write_auth, attacker)

    incident = db.execute("SELECT * FROM incidents").fetchone()
    assert incident["status"] == "open"


def test_a_failed_action_is_retried_on_the_next_evaluation(client, write_auth, db, attacker):
    multi_stage(client, write_auth, attacker)
    incident_id = db.execute("SELECT id FROM incidents").fetchone()["id"]
    db.execute("UPDATE responses SET result = 'failed' WHERE action = %s", (BLOCK,))
    db.execute("DELETE FROM blocked_sources")

    with psycopg.connect(db.info.dsn, row_factory=psycopg.rows.dict_row) as conn:
        outcome = respond_to_incident(conn, incident_id, actor="retry")
        conn.commit()

    results = {a["action"]: a["result"] for a in outcome["actions"]}
    assert results[BLOCK] == config.RESULT_EXECUTED
    assert db.execute("SELECT count(*) AS n FROM blocked_sources").fetchone()["n"] == 1


def test_response_failure_does_not_discard_the_detection(client, write_auth, db, attacker, monkeypatch):
    from sentinelmesh import response as response_module

    def broken(conn, incident_id, actor, threat_id=None):
        raise RuntimeError("simulated response fault")

    monkeypatch.setattr("sentinelmesh.detection.respond_to_incident", broken)
    brute_force(client, write_auth)

    assert db.execute("SELECT count(*) AS n FROM threats").fetchone()["n"] == 1
    assert db.execute("SELECT count(*) AS n FROM incidents").fetchone()["n"] == 1
    assert db.execute("SELECT count(*) AS n FROM responses").fetchone()["n"] == 0


# --- integration: API and tampering ------------------------------------------


def test_respond_endpoint_requires_the_respond_scope(client, write_auth, read_auth, respond_auth, db, attacker):
    multi_stage(client, write_auth, attacker)
    incident_id = db.execute("SELECT id FROM incidents").fetchone()["id"]

    assert client.post(f"{INCIDENTS}{incident_id}/respond/").status_code == 401
    assert client.post(f"{INCIDENTS}{incident_id}/respond/", headers=read_auth).status_code == 403
    assert client.post(f"{INCIDENTS}{incident_id}/respond/", headers=write_auth).status_code == 403
    assert client.post(f"{INCIDENTS}{incident_id}/respond/", headers=respond_auth).status_code == 200


def test_respond_endpoint_is_idempotent(client, write_auth, respond_auth, db, attacker):
    multi_stage(client, write_auth, attacker)
    incident_id = db.execute("SELECT id FROM incidents").fetchone()["id"]

    body = client.post(f"{INCIDENTS}{incident_id}/respond/", headers=respond_auth).get_json()

    assert all(a["result"] == config.RESULT_ALREADY_APPLIED for a in body["actions"])
    assert db.execute("SELECT count(*) AS n FROM responses").fetchone()["n"] == 5


def test_respond_endpoint_404s_for_an_unknown_incident(client, respond_auth):
    assert client.post(f"{INCIDENTS}999999/respond/", headers=respond_auth).status_code == 404


@pytest.mark.parametrize(
    "field,value",
    [
        ("action", "isolate_device"),
        ("result", "succeeded"),
        ("risk", 0),
        ("policy", "safe"),
        ("incident_risk", 0),
        ("severity", "low"),
        ("actions", []),
    ],
)
def test_client_cannot_choose_the_response(client, write_auth, respond_auth, db, attacker, field, value):
    multi_stage(client, write_auth, attacker)
    incident_id = db.execute("SELECT id FROM incidents").fetchone()["id"]

    response = client.post(f"{INCIDENTS}{incident_id}/respond/", json={field: value}, headers=respond_auth)

    assert response.status_code == 400
    assert any(d["field"] == field for d in response.get_json()["error"]["details"])


def test_client_cannot_contain_an_arbitrary_subject(client, respond_auth, db, make_user):
    """There is no API that takes a user or address to contain."""
    victim = make_user("m.acheampong", "admin")

    assert client.post("/api/users/contain/", headers=respond_auth).status_code in (404, 405)
    assert client.post("/api/devices/isolate/", headers=respond_auth).status_code in (404, 405)
    assert db.execute("SELECT contained FROM users WHERE id = %s", (victim,)).fetchone()["contained"] is False


# --- integration: audit ------------------------------------------------------


def test_every_action_is_audited(client, write_auth, read_auth, db, attacker):
    multi_stage(client, write_auth, attacker)

    data = client.get(RESPONSES, headers=read_auth).get_json()["data"]

    assert {d["action"] for d in data} == {ALERT, STEP_UP, CONTAIN, BLOCK, ISOLATE}
    for record in data:
        assert record["policy"] and record["reason"] and record["actor"]
        assert record["evidence"]["plan"]["model_version"] == config.RESPONSE_MODEL_VERSION
        assert record["occurred_at"]


def test_audit_records_the_trigger_and_actor(client, write_auth, db, attacker):
    multi_stage(client, write_auth, attacker)

    rows = db.execute("SELECT DISTINCT actor, threat_id FROM responses").fetchall()
    assert all(r["actor"] == "engine" for r in rows)
    assert all(r["threat_id"] is not None for r in rows)


def test_audit_survives_and_does_not_change_when_threats_change(client, write_auth, db, attacker):
    multi_stage(client, write_auth, attacker)
    snapshot = actions_for(db)[CONTAIN]

    brute_force(client, write_auth, ip="198.51.100.9", start=900)

    reloaded = actions_for(db)[CONTAIN]
    assert reloaded["result"] == snapshot["result"]
    assert reloaded["reason"] == snapshot["reason"]
    assert reloaded["occurred_at"] == snapshot["occurred_at"]


def test_audit_contains_no_credentials(client, write_auth, db, attacker):
    multi_stage(client, write_auth, attacker)

    rendered = str(db.execute("SELECT evidence FROM responses").fetchall())
    for secret in ["test-write-secret", "test-decide-secret", "test-respond-secret", "Bearer"]:
        assert secret not in rendered


def test_responses_filter_by_incident(client, write_auth, read_auth, db, attacker):
    multi_stage(client, write_auth, attacker)
    incident_id = db.execute("SELECT id FROM incidents").fetchone()["id"]

    data = client.get(f"{RESPONSES}?incident_id={incident_id}", headers=read_auth).get_json()["data"]
    assert len(data) == 5
    assert client.get(f"{RESPONSES}?incident_id=999999", headers=read_auth).get_json()["data"] == []


def test_incident_detail_shows_the_response_chain(client, write_auth, read_auth, db, attacker):
    multi_stage(client, write_auth, attacker)
    incident_id = db.execute("SELECT id FROM incidents").fetchone()["id"]

    body = client.get(f"{INCIDENTS}{incident_id}", headers=read_auth).get_json()

    assert len(body["threats"]) == 3
    assert {r["action"] for r in body["responses"]} == {ALERT, STEP_UP, CONTAIN, BLOCK, ISOLATE}
    assert body["timeline"]


def test_responses_endpoint_requires_read_scope(client, respond_auth):
    assert client.get(RESPONSES).status_code == 401
    assert client.get(RESPONSES, headers=respond_auth).status_code == 403


# --- integration: context loading --------------------------------------------


def test_context_scopes_devices_to_the_incident(client, write_auth, db, attacker):
    """A device the user owns but that took no part must not be isolated."""
    db.execute(
        "INSERT INTO devices (user_id, device_fingerprint, trust_score) VALUES (%s, 'fp-uninvolved', 90)",
        (attacker,),
    )
    multi_stage(client, write_auth, attacker)

    isolated = db.execute("SELECT device_fingerprint FROM devices WHERE isolated").fetchall()
    assert [d["device_fingerprint"] for d in isolated] == ["fp-dead-vm"]


def test_context_returns_none_for_a_missing_incident(db):
    with psycopg.connect(db.info.dsn, row_factory=psycopg.rows.dict_row) as conn:
        assert load_response_context(conn, 999999) is None
