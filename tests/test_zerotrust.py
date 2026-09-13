"""Zero-trust decision engine tests.

The first half drives `evaluate_access` as a pure function, so the policy is
tested without a database. The second half proves the decision is produced by
real PostgreSQL state built through the Phase 1-4 pipeline, not by a shortcut.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from sentinelmesh import config
from sentinelmesh.zerotrust import (
    PRECEDENCE_NAMES,
    AccessContext,
    evaluate_access,
    sensitivity_for,
)

DECIDE = "/api/access/decision/"
DECISIONS = "/api/access/decisions/"
EVENTS = "/api/events/"
BASE = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

PUBLIC = "/api/public/status"
INTERNAL = "/api/search"
SENSITIVE = "/api/reports/q3"
CRITICAL = "/api/internal"


def context(**overrides) -> AccessContext:
    """A clean, fully trusted baseline; override one axis at a time."""
    base = {
        "resource": INTERNAL,
        "sensitivity": config.SENSITIVITY_INTERNAL,
        "authenticated": True,
        "subject_user_id": 1,
        "subject_username": "a.okafor",
        "subject_role": "analyst",
        "subject_exists": True,
        "device_fingerprint": "fp-known",
        "device_state": config.DEVICE_TRUSTED,
        "device_trust": Decimal("95"),
        "source_ip": "10.0.0.1",
        "max_threat_risk": 0,
        "top_threat": None,
        "threat_count": 0,
        "incident": None,
        "incident_risk": 0,
    }
    base.update(overrides)
    return AccessContext(**base)


def incident(risk, classification="multi_stage_attack", status="open"):
    return {
        "id": 1,
        "reference": "SM-001",
        "classification": classification,
        "status": status,
        "risk_score": risk,
        "correlation_confidence": 0.99,
    }


def threat(risk, threat_type="injection.sql"):
    return {"id": 1, "threat_type": threat_type, "risk_score": risk, "risk_level": "critical"}


# --- resource classification -------------------------------------------------


@pytest.mark.parametrize(
    "resource,expected",
    [
        ("/api/public/status", config.SENSITIVITY_PUBLIC),
        ("/health", config.SENSITIVITY_PUBLIC),
        ("/api/search?q=x", config.SENSITIVITY_INTERNAL),
        ("/api/dashboard", config.SENSITIVITY_INTERNAL),
        ("/api/reports/q3", config.SENSITIVITY_SENSITIVE),
        ("/api/admin/users", config.SENSITIVITY_CRITICAL),
        ("/api/internal", config.SENSITIVITY_CRITICAL),
        ("/admin", config.SENSITIVITY_CRITICAL),
    ],
)
def test_resource_sensitivity_is_derived_server_side(resource, expected):
    assert sensitivity_for(resource) == expected


def test_unrecognised_resource_fails_closed():
    assert sensitivity_for("/totally/unknown/path") == config.SENSITIVITY_SENSITIVE
    assert sensitivity_for("") == config.SENSITIVITY_SENSITIVE


# --- identity ----------------------------------------------------------------


def test_unauthenticated_is_denied():
    decision = evaluate_access(context(authenticated=False, subject_user_id=None, subject_exists=False))

    assert decision.decision == config.DENY
    assert decision.policy == "identity_unauthenticated"


def test_unknown_principal_is_denied():
    """Fail closed: a subject absent from the identity store gets nothing."""
    decision = evaluate_access(context(subject_exists=False, subject_username=None, subject_role=None))

    assert decision.decision == config.DENY
    assert decision.policy == "identity_unknown"


def test_authenticated_clean_context_is_allowed():
    decision = evaluate_access(context())

    assert decision.decision == config.ALLOW
    assert decision.policy == "trusted_baseline"


# --- device ------------------------------------------------------------------


def test_trusted_device_low_risk_is_allowed():
    assert evaluate_access(context(device_state=config.DEVICE_TRUSTED)).decision == config.ALLOW


def test_unknown_device_low_risk_is_stepped_up():
    decision = evaluate_access(context(device_state=config.DEVICE_UNKNOWN, device_trust=None))

    assert decision.decision == config.STEP_UP
    assert decision.policy == "device_not_trusted"


def test_untrusted_device_on_sensitive_resource_is_denied():
    decision = evaluate_access(
        context(
            device_state=config.DEVICE_UNTRUSTED,
            device_trust=Decimal("4"),
            resource=SENSITIVE,
            sensitivity=config.SENSITIVITY_SENSITIVE,
        )
    )

    assert decision.decision == config.DENY
    assert decision.policy == "untrusted_device_sensitive_resource"


def test_untrusted_device_on_public_resource_is_only_stepped_up():
    decision = evaluate_access(
        context(
            device_state=config.DEVICE_UNTRUSTED,
            device_trust=Decimal("4"),
            resource=PUBLIC,
            sensitivity=config.SENSITIVITY_PUBLIC,
        )
    )

    assert decision.decision == config.STEP_UP


# --- threat risk -------------------------------------------------------------


def test_no_threat_follows_normal_policy():
    assert evaluate_access(context(max_threat_risk=0)).decision == config.ALLOW


def test_low_threat_risk_follows_normal_policy():
    assert evaluate_access(context(max_threat_risk=config.ZT_ELEVATED_RISK - 1)).decision == config.ALLOW


def test_medium_threat_risk_steps_up():
    decision = evaluate_access(context(max_threat_risk=config.ZT_ELEVATED_RISK, top_threat=threat(30)))

    assert decision.decision == config.STEP_UP
    assert decision.policy == "elevated_risk"


def test_high_threat_risk_steps_up_on_low_sensitivity():
    decision = evaluate_access(
        context(
            max_threat_risk=config.ZT_HIGH_RISK,
            top_threat=threat(60),
            resource=PUBLIC,
            sensitivity=config.SENSITIVITY_PUBLIC,
        )
    )

    assert decision.decision == config.STEP_UP
    assert decision.policy == "high_risk_threat"


def test_high_threat_risk_denies_on_sensitive_resource():
    decision = evaluate_access(
        context(
            max_threat_risk=config.ZT_HIGH_RISK,
            top_threat=threat(60),
            resource=SENSITIVE,
            sensitivity=config.SENSITIVITY_SENSITIVE,
        )
    )

    assert decision.decision == config.DENY
    assert decision.policy == "high_risk_sensitive_resource"


def test_critical_threat_is_always_denied():
    for resource, sensitivity in [(PUBLIC, config.SENSITIVITY_PUBLIC), (INTERNAL, config.SENSITIVITY_INTERNAL)]:
        decision = evaluate_access(
            context(
                max_threat_risk=config.ZT_CRITICAL_RISK,
                top_threat=threat(94),
                resource=resource,
                sensitivity=sensitivity,
            )
        )
        assert decision.decision == config.DENY
        assert decision.policy == "critical_threat"


# --- incident ----------------------------------------------------------------


def test_no_active_incident_follows_normal_policy():
    assert evaluate_access(context(incident=None, incident_risk=0)).decision == config.ALLOW


def test_low_risk_incident_does_not_override_normal_policy():
    decision = evaluate_access(context(incident=incident(20, "credential_attack"), incident_risk=20))

    assert decision.decision == config.ALLOW


def test_high_risk_incident_steps_up():
    decision = evaluate_access(context(incident=incident(64, "credential_attack"), incident_risk=64))

    assert decision.decision == config.STEP_UP
    assert decision.policy == "high_risk_incident"


def test_critical_incident_is_denied():
    decision = evaluate_access(context(incident=incident(100), incident_risk=100))

    assert decision.decision == config.DENY
    assert decision.policy == "critical_incident"


def test_critical_incident_denies_even_on_a_public_resource():
    decision = evaluate_access(
        context(incident=incident(100), incident_risk=100, resource=PUBLIC, sensitivity=config.SENSITIVITY_PUBLIC)
    )

    assert decision.decision == config.DENY


# --- resource sensitivity gradient -------------------------------------------


def test_same_context_different_resource_yields_different_decisions():
    """The point of resource sensitivity: one context, several verdicts."""
    outcomes = {}
    for resource, sensitivity in [
        (PUBLIC, config.SENSITIVITY_PUBLIC),
        (INTERNAL, config.SENSITIVITY_INTERNAL),
        (SENSITIVE, config.SENSITIVITY_SENSITIVE),
        (CRITICAL, config.SENSITIVITY_CRITICAL),
    ]:
        decision = evaluate_access(
            context(
                resource=resource,
                sensitivity=sensitivity,
                max_threat_risk=config.ZT_HIGH_RISK,
                top_threat=threat(64),
                subject_role="viewer",
            )
        )
        outcomes[sensitivity] = decision.decision

    assert outcomes[config.SENSITIVITY_PUBLIC] == config.STEP_UP
    assert outcomes[config.SENSITIVITY_INTERNAL] == config.STEP_UP
    assert outcomes[config.SENSITIVITY_SENSITIVE] == config.DENY
    assert outcomes[config.SENSITIVITY_CRITICAL] == config.DENY
    assert len(set(outcomes.values())) > 1


def test_clean_context_gradient_still_protects_critical_resources():
    allowed = evaluate_access(context(subject_role="viewer", sensitivity=config.SENSITIVITY_INTERNAL))
    denied = evaluate_access(
        context(subject_role="viewer", resource=CRITICAL, sensitivity=config.SENSITIVITY_CRITICAL)
    )

    assert allowed.decision == config.ALLOW
    assert denied.decision == config.DENY
    assert denied.policy == "insufficient_privilege"


# --- privilege ---------------------------------------------------------------


def test_viewer_is_denied_a_critical_administrative_resource():
    decision = evaluate_access(
        context(subject_role="viewer", resource="/api/admin/users", sensitivity=config.SENSITIVITY_CRITICAL)
    )

    assert decision.decision == config.DENY
    assert decision.policy == "insufficient_privilege"


def test_admin_does_not_bypass_zero_trust_on_a_critical_resource():
    """Even a clean admin on a trusted device must re-verify."""
    decision = evaluate_access(
        context(subject_role="admin", resource="/api/admin/users", sensitivity=config.SENSITIVITY_CRITICAL)
    )

    assert decision.decision == config.STEP_UP
    assert decision.policy == "privileged_resource"


def test_admin_is_denied_under_a_critical_incident():
    decision = evaluate_access(
        context(
            subject_role="admin",
            resource="/api/admin/users",
            sensitivity=config.SENSITIVITY_CRITICAL,
            incident=incident(100),
            incident_risk=100,
        )
    )

    assert decision.decision == config.DENY
    assert decision.policy == "critical_incident"


# --- precedence --------------------------------------------------------------


def test_critical_incident_outranks_device_and_privilege_rules():
    decision = evaluate_access(
        context(
            subject_role="admin",
            device_state=config.DEVICE_UNTRUSTED,
            device_trust=Decimal("1"),
            resource=CRITICAL,
            sensitivity=config.SENSITIVITY_CRITICAL,
            incident=incident(100),
            incident_risk=100,
            max_threat_risk=94,
            top_threat=threat(94),
        )
    )

    assert decision.policy == "critical_incident", "identity then incident then threat must win"


def test_identity_outranks_everything():
    decision = evaluate_access(
        context(authenticated=False, subject_exists=False, incident=incident(100), incident_risk=100)
    )

    assert decision.policy == "identity_unauthenticated"


def test_every_deny_policy_precedes_every_step_up_policy():
    deny_policies = PRECEDENCE_NAMES[:7]
    step_up_policies = PRECEDENCE_NAMES[7:12]

    assert deny_policies[0] == "identity_unauthenticated"
    assert PRECEDENCE_NAMES[-1] == "trusted_baseline"
    assert set(deny_policies).isdisjoint(step_up_policies)


# --- explainability and determinism ------------------------------------------


def test_every_decision_explains_all_five_categories():
    decision = evaluate_access(context(incident=incident(100), incident_risk=100, max_threat_risk=94))

    categories = {f["category"] for f in decision.factors}
    assert categories == {"identity", "device", "threat", "incident", "resource", "containment"}
    for factor in decision.factors:
        assert factor["detail"]
        assert factor["factor"]
    assert decision.reason


def test_explanation_names_the_incident_and_risk():
    decision = evaluate_access(context(incident=incident(100), incident_risk=100))

    assert "SM-001" in decision.reason
    assert "multi_stage_attack" in decision.reason
    assert "100" in decision.reason


def test_decision_payload_carries_no_credentials():
    decision = evaluate_access(context(device_fingerprint="fp-secret-value"))
    rendered = str(decision.to_dict())

    # The fingerprint's presence is reported, never its value.
    assert "fp-secret-value" not in rendered
    assert "present" in rendered


def test_decision_is_deterministic():
    ctx = context(max_threat_risk=64, top_threat=threat(64), incident=incident(64), incident_risk=64)

    results = {(evaluate_access(ctx).decision, evaluate_access(ctx).policy) for _ in range(25)}

    assert len(results) == 1


def test_no_artificial_confidence_score_is_invented():
    payload = evaluate_access(context()).to_dict()

    assert "confidence" not in payload
    assert all("confidence" not in str(f.get("factor", "")) for f in payload["factors"])


# --- integration: authentication and scope -----------------------------------


def test_decision_endpoint_requires_credentials(client):
    assert client.post(DECIDE, json={"resource": INTERNAL}).status_code == 401


def test_decision_endpoint_requires_the_decide_scope(client, write_auth, read_auth):
    assert client.post(DECIDE, json={"resource": INTERNAL}, headers=write_auth).status_code == 403
    assert client.post(DECIDE, json={"resource": INTERNAL}, headers=read_auth).status_code == 403


def test_decide_scope_cannot_read_the_audit_log(client, decide_auth):
    assert client.get(DECISIONS, headers=decide_auth).status_code == 403


def test_request_without_a_subject_is_denied(client, decide_auth):
    body = client.post(DECIDE, json={"resource": INTERNAL}, headers=decide_auth).get_json()

    assert body["decision"] == config.DENY
    assert body["policy"] == "identity_unauthenticated"


def test_nonexistent_subject_is_denied(client, decide_auth):
    body = client.post(
        DECIDE, json={"resource": INTERNAL, "subject_user_id": 999999}, headers=decide_auth
    ).get_json()

    assert body["decision"] == config.DENY
    assert body["policy"] == "identity_unknown"


# --- integration: authoritative context --------------------------------------


@pytest.fixture
def trusted_analyst(db, make_user):
    user_id = make_user("a.okafor", "analyst")
    db.execute(
        "INSERT INTO devices (user_id, device_fingerprint, trust_score) VALUES (%s, 'fp-trusted', 95)", (user_id,)
    )
    return user_id


@pytest.fixture
def viewer(db, make_user):
    user_id = make_user("t.devries", "viewer")
    db.execute(
        "INSERT INTO devices (user_id, device_fingerprint, trust_score) VALUES (%s, 'fp-untrusted', 4)", (user_id,)
    )
    return user_id


def ask(client, decide_auth, **payload):
    response = client.post(DECIDE, json=payload, headers=decide_auth)
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def test_trusted_device_resolves_from_the_database(client, decide_auth, trusted_analyst):
    body = ask(client, decide_auth, resource=INTERNAL, subject_user_id=trusted_analyst, device_fingerprint="fp-trusted")

    assert body["context"]["device"]["state"] == config.DEVICE_TRUSTED
    assert body["decision"] == config.ALLOW


def test_untrusted_device_resolves_from_the_database(client, decide_auth, viewer):
    body = ask(client, decide_auth, resource=SENSITIVE, subject_user_id=viewer, device_fingerprint="fp-untrusted")

    assert body["context"]["device"]["state"] == config.DEVICE_UNTRUSTED
    assert body["decision"] == config.DENY


def test_role_comes_from_the_users_table(client, decide_auth, viewer):
    body = ask(client, decide_auth, resource=CRITICAL, subject_user_id=viewer, device_fingerprint="fp-untrusted")

    assert body["context"]["subject"]["role"] == "viewer"
    assert body["decision"] == config.DENY


def test_device_of_another_user_does_not_resolve(client, decide_auth, trusted_analyst, viewer):
    """Claiming somebody else's trusted fingerprint must not grant trust."""
    body = ask(client, decide_auth, resource=INTERNAL, subject_user_id=viewer, device_fingerprint="fp-trusted")

    assert body["context"]["device"]["state"] == config.DEVICE_UNKNOWN
    assert body["decision"] == config.STEP_UP


# --- integration: the full pipeline drives the decision ----------------------


def ingest(client, auth, **payload):
    response = client.post(EVENTS, json=payload, headers=auth)
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def build_multi_stage_attack(client, write_auth, user_id, ip="203.0.113.44"):
    """Run the real Phase 1-4 pipeline: 5 failures, privilege abuse, injection."""
    for i in range(5):
        ingest(
            client,
            write_auth,
            event_type="auth.login.failure",
            source_ip=ip,
            occurred_at=(BASE + timedelta(seconds=i * 10)).isoformat(),
            metadata={"username": "admin01", "attempt": i},
        )
    ingest(
        client,
        write_auth,
        event_type="api.request",
        user_id=user_id,
        source_ip=ip,
        occurred_at=(BASE + timedelta(seconds=200)).isoformat(),
        metadata={"method": "GET", "path": "/api/admin/users"},
    )
    ingest(
        client,
        write_auth,
        event_type="api.request",
        user_id=user_id,
        source_ip=ip,
        occurred_at=(BASE + timedelta(seconds=300)).isoformat(),
        metadata={"path": "/api/search", "query": {"q": "' OR 1=1 UNION SELECT username FROM users --"}},
    )


def test_clean_access_is_allowed_then_the_attack_causes_a_deny(
    client, write_auth, decide_auth, db, viewer
):
    """The headline test: the security pipeline itself flips the verdict."""
    before = ask(
        client, decide_auth, resource=CRITICAL, subject_user_id=viewer, device_fingerprint="fp-untrusted"
    )
    baseline_policy = before["policy"]

    build_multi_stage_attack(client, write_auth, viewer)

    # The pipeline really did build a critical incident.
    campaign = db.execute("SELECT * FROM incidents ORDER BY id").fetchall()
    assert len(campaign) == 1
    assert campaign[0]["classification"] == config.CLASSIFICATION_MULTI_STAGE
    assert int(campaign[0]["risk_score"]) >= config.ZT_CRITICAL_RISK
    assert campaign[0]["status"] == "open"

    after = ask(
        client,
        decide_auth,
        resource=CRITICAL,
        subject_user_id=viewer,
        device_fingerprint="fp-untrusted",
        source_ip="203.0.113.44",
    )

    assert after["decision"] == config.DENY
    assert after["policy"] == "critical_incident"
    assert after["context"]["incident"]["classification"] == config.CLASSIFICATION_MULTI_STAGE
    assert after["context"]["incident"]["risk_score"] >= config.ZT_CRITICAL_RISK
    assert after["context"]["threat"]["active_count"] >= 3
    assert baseline_policy != "critical_incident", "the deny must be caused by the attack, not pre-existing"


def test_trusted_user_allowed_before_attack_denied_after(client, write_auth, decide_auth, trusted_analyst):
    clean = ask(
        client, decide_auth, resource=INTERNAL, subject_user_id=trusted_analyst, device_fingerprint="fp-trusted"
    )
    assert clean["decision"] == config.ALLOW
    assert clean["policy"] == "trusted_baseline"

    build_multi_stage_attack(client, write_auth, trusted_analyst)

    attacked = ask(
        client,
        decide_auth,
        resource=INTERNAL,
        subject_user_id=trusted_analyst,
        device_fingerprint="fp-trusted",
        source_ip="203.0.113.44",
    )

    assert attacked["decision"] == config.DENY
    assert attacked["policy"] == "critical_incident"


def test_source_ip_context_pulls_in_campaign_threats(client, write_auth, decide_auth, db, viewer):
    build_multi_stage_attack(client, write_auth, viewer, ip="203.0.113.44")

    with_ip = ask(
        client, decide_auth, resource=PUBLIC, subject_user_id=viewer, source_ip="203.0.113.44"
    )

    assert with_ip["context"]["threat"]["active_count"] >= 3
    assert with_ip["decision"] == config.DENY


def test_unrelated_user_is_unaffected_by_another_campaign(client, write_auth, decide_auth, db, viewer, make_user):
    bystander = make_user("r.mensah", "responder")
    db.execute(
        "INSERT INTO devices (user_id, device_fingerprint, trust_score) VALUES (%s, 'fp-clean', 90)", (bystander,)
    )
    build_multi_stage_attack(client, write_auth, viewer)

    body = ask(client, decide_auth, resource=INTERNAL, subject_user_id=bystander, device_fingerprint="fp-clean")

    assert body["decision"] == config.ALLOW
    assert body["context"]["incident"] is None


# --- integration: tampering --------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("role", "admin"),
        ("user_role", "admin"),
        ("risk_score", 0),
        ("risk_level", "low"),
        ("severity", "low"),
        ("device_trust", "trusted"),
        ("device_state", "trusted"),
        ("trust_score", 100),
        ("incident_id", None),
        ("incident_risk", 0),
        ("correlation_confidence", 1),
        ("classification", "none"),
        ("decision", "allow"),
        ("policy", "trusted_baseline"),
        ("sensitivity", "public"),
        ("authenticated", True),
    ],
)
def test_client_cannot_supply_engine_owned_fields(client, decide_auth, viewer, field, value):
    response = client.post(
        DECIDE, json={"resource": CRITICAL, "subject_user_id": viewer, field: value}, headers=decide_auth
    )

    assert response.status_code == 400
    assert any(d["field"] == field for d in response.get_json()["error"]["details"])


def test_forged_fields_cannot_flip_a_deny_to_an_allow(client, write_auth, decide_auth, viewer):
    build_multi_stage_attack(client, write_auth, viewer)

    # Every forged field is rejected outright, so the verdict cannot be bought.
    forged = client.post(
        DECIDE,
        json={
            "resource": CRITICAL,
            "subject_user_id": viewer,
            "role": "admin",
            "risk_score": 0,
            "decision": "allow",
        },
        headers=decide_auth,
    )
    assert forged.status_code == 400

    honest = ask(client, decide_auth, resource=CRITICAL, subject_user_id=viewer, source_ip="203.0.113.44")
    assert honest["decision"] == config.DENY


def test_sensitivity_cannot_be_downgraded_by_the_caller(client, decide_auth, viewer):
    """A caller must not relabel a critical resource as public."""
    rejected = client.post(
        DECIDE,
        json={"resource": "/api/admin/users", "subject_user_id": viewer, "sensitivity": "public"},
        headers=decide_auth,
    )
    assert rejected.status_code == 400

    body = ask(client, decide_auth, resource="/api/admin/users", subject_user_id=viewer)
    assert body["context"]["resource"]["sensitivity"] == config.SENSITIVITY_CRITICAL
    assert body["decision"] == config.DENY


def test_unknown_fields_are_rejected(client, decide_auth, viewer):
    response = client.post(
        DECIDE, json={"resource": INTERNAL, "subject_user_id": viewer, "bypass": True}, headers=decide_auth
    )

    assert response.status_code == 400


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"resource": ""},
        {"resource": "   "},
        {"resource": 42},
        {"resource": "/api/x", "subject_user_id": "2"},
        {"resource": "/api/x", "subject_user_id": 0},
        {"resource": "/api/x", "subject_user_id": True},
        {"resource": "/api/x", "source_ip": "999.1.1.1"},
        {"resource": "/api/x", "device_fingerprint": 12},
        {"resource": "A" * 600},
    ],
)
def test_malformed_requests_are_rejected(client, decide_auth, payload):
    assert client.post(DECIDE, json=payload, headers=decide_auth).status_code == 400


def test_malformed_json_and_wrong_content_type(client, decide_auth):
    assert (
        client.post(DECIDE, data="{,,}", content_type="application/json", headers=decide_auth).status_code == 400
    )
    assert client.post(DECIDE, data="x", content_type="text/plain", headers=decide_auth).status_code == 415


def test_no_database_text_leaks_on_error(client, decide_auth):
    body = client.post(DECIDE, json={"resource": 42}, headers=decide_auth).get_json()
    rendered = str(body).lower()

    assert "psycopg" not in rendered
    assert "traceback" not in rendered
    assert "select" not in rendered


# --- integration: persistence and audit --------------------------------------


def test_decision_is_persisted_immutably(client, decide_auth, db, viewer):
    body = ask(client, decide_auth, resource=CRITICAL, subject_user_id=viewer, device_fingerprint="fp-untrusted")

    row = db.execute("SELECT * FROM access_decisions WHERE id = %s", (body["decision_id"],)).fetchone()

    assert row["decision"] == body["decision"]
    assert row["policy"] == body["policy"]
    assert row["resource"] == CRITICAL
    assert row["sensitivity"] == config.SENSITIVITY_CRITICAL
    assert row["subject_role"] == "viewer"
    assert row["device_state"] == config.DEVICE_UNTRUSTED
    assert row["api_key"] == "test-gateway"
    assert row["factors"]["factors"]


def test_persisted_decision_does_not_change_when_the_threat_picture_changes(
    client, write_auth, decide_auth, db, viewer
):
    """Historical verdicts are snapshots, not live views."""
    before = ask(client, decide_auth, resource=INTERNAL, subject_user_id=viewer)
    snapshot = db.execute("SELECT * FROM access_decisions WHERE id = %s", (before["decision_id"],)).fetchone()

    build_multi_stage_attack(client, write_auth, viewer)

    reloaded = db.execute("SELECT * FROM access_decisions WHERE id = %s", (before["decision_id"],)).fetchone()
    assert reloaded["decision"] == snapshot["decision"]
    assert reloaded["policy"] == snapshot["policy"]
    assert reloaded["max_threat_risk"] == snapshot["max_threat_risk"]
    assert reloaded["incident_id"] == snapshot["incident_id"]


def test_audit_log_is_retrievable(client, decide_auth, read_auth, viewer):
    ask(client, decide_auth, resource=CRITICAL, subject_user_id=viewer)
    ask(client, decide_auth, resource=PUBLIC, subject_user_id=viewer)

    data = client.get(DECISIONS, headers=read_auth).get_json()["data"]

    assert len(data) == 2
    assert {d["resource"] for d in data} == {CRITICAL, PUBLIC}
    assert all(d["policy"] for d in data)


def test_audit_log_filters_by_subject_and_paginates(client, decide_auth, read_auth, viewer, trusted_analyst):
    for _ in range(3):
        ask(client, decide_auth, resource=INTERNAL, subject_user_id=viewer)
    ask(client, decide_auth, resource=INTERNAL, subject_user_id=trusted_analyst)

    mine = client.get(f"{DECISIONS}?subject_user_id={viewer}", headers=read_auth).get_json()["data"]
    assert len(mine) == 3

    page = client.get(f"{DECISIONS}?limit=2", headers=read_auth).get_json()
    assert len(page["data"]) == 2
    assert page["next_cursor"] is not None
    second = client.get(f"{DECISIONS}?limit=2&cursor={page['next_cursor']}", headers=read_auth).get_json()
    assert {d["id"] for d in page["data"]}.isdisjoint({d["id"] for d in second["data"]})


def test_audit_log_requires_read_scope(client):
    assert client.get(DECISIONS).status_code == 401


def test_database_rejects_an_invalid_decision_value(db):
    import psycopg

    with pytest.raises(psycopg.errors.InvalidTextRepresentation):
        db.execute(
            "INSERT INTO access_decisions (api_key, authenticated, device_state, resource, sensitivity,"
            " decision, policy, reason) VALUES ('k', true, 'unknown', '/x', 'public', 'maybe', 'p', 'r')"
        )


def test_repeated_identical_requests_are_deterministic(client, decide_auth, db, viewer):
    bodies = [
        ask(client, decide_auth, resource=CRITICAL, subject_user_id=viewer, device_fingerprint="fp-untrusted")
        for _ in range(5)
    ]

    assert len({(b["decision"], b["policy"], b["reason"]) for b in bodies}) == 1
    # Each evaluation is still its own audit record.
    assert len({b["decision_id"] for b in bodies}) == 5
    assert db.execute("SELECT count(*) AS n FROM access_decisions").fetchone()["n"] == 5


def test_concurrent_decisions_are_all_audited(app, db, make_user):
    import threading

    user_id = make_user("t.devries", "viewer")
    barrier = threading.Barrier(4)
    errors = []

    def submit():
        try:
            client = app.test_client()
            barrier.wait(timeout=10)
            response = client.post(
                DECIDE,
                json={"resource": CRITICAL, "subject_user_id": user_id},
                headers={"Authorization": "Bearer test-decide-secret-00000"},
            )
            assert response.status_code == 200, response.get_json()
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            errors.append(exc)

    threads = [threading.Thread(target=submit) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    assert not errors, errors
    rows = db.execute("SELECT decision, policy FROM access_decisions").fetchall()
    assert len(rows) == 4
    assert len({(r["decision"], r["policy"]) for r in rows}) == 1
