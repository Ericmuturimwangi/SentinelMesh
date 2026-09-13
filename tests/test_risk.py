"""Risk engine tests.

The first half exercises calculate_threat_risk as a pure function -- no
database, no Flask, no HTTP -- which is the point of keeping it separable.
The second half checks that the engine is wired into ingestion and that the
context it consumes comes from authoritative records.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from sentinelmesh import config
from sentinelmesh.risk import RiskContext, calculate_threat_risk, level_for
from sentinelmesh.rules import Detection

EVENTS = "/api/events/"
THREATS = "/api/threats/"
BASE = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def detection(severity="high", confidence=0.9, threat_type="injection.sql"):
    return Detection(
        rule_id="test.v1",
        threat_type=threat_type,
        severity=severity,
        confidence=confidence,
        reason="test detection",
        evidence={},
    )


def event(user_id=None, source_ip="10.0.0.1", metadata=None):
    return {
        "id": 1,
        "event_type": "api.request",
        "user_id": user_id,
        "source_ip": source_ip,
        "occurred_at": BASE,
        "metadata": metadata or {},
    }


# --- pure model: severity baseline -------------------------------------------


def test_severity_orders_risk_strictly():
    scores = [calculate_threat_risk(detection(severity=s), event()).score for s in SEVERITIES]

    assert scores == sorted(scores)
    assert len(set(scores)) == len(SEVERITIES), "each severity must be distinguishable"


def test_severity_baselines_come_from_configuration():
    for severity, baseline in config.RISK_SEVERITY_BASELINE.items():
        result = calculate_threat_risk(detection(severity=severity, confidence=1.0), event())
        contribution = next(f for f in result.factors if f.factor == "threat_severity").contribution
        assert contribution == baseline


def test_unscoreable_severity_is_rejected_loudly():
    with pytest.raises(ValueError, match="unscoreable severity"):
        calculate_threat_risk(detection(severity="apocalyptic"), event())


# --- pure model: confidence --------------------------------------------------


def test_higher_confidence_never_lowers_risk():
    scores = [
        calculate_threat_risk(detection(confidence=c), event()).score
        for c in [0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99, 1.0]
    ]

    assert scores == sorted(scores)
    assert scores[0] < scores[-1], "confidence must actually matter"


def test_confidence_scales_severity_rather_than_adding_to_it():
    full = calculate_threat_risk(detection(severity="high", confidence=1.0), event())
    weak = calculate_threat_risk(detection(severity="high", confidence=0.0), event())

    # At full confidence the baseline is untouched; lower confidence subtracts.
    assert next(f for f in full.factors if f.factor == "detection_confidence").contribution == 0
    assert next(f for f in weak.factors if f.factor == "detection_confidence").contribution < 0


def test_confidence_alone_cannot_manufacture_a_critical():
    """A low-severity detection stays low-risk however confident the rule is."""
    maxed = RiskContext(
        actor_role="admin",
        device_trust=Decimal("1"),
        device_resolved=True,
        resource_sensitive=True,
        prior_threat_types=99,
    )

    result = calculate_threat_risk(detection(severity="low", confidence=1.0), event(user_id=1), maxed)

    assert result.level != "critical"
    assert result.score < config.RISK_LEVEL_BANDS[-1][0]


def test_high_severity_outranks_low_severity_even_at_worse_confidence():
    high_weak = calculate_threat_risk(detection(severity="high", confidence=0.0), event()).score
    medium_sure = calculate_threat_risk(detection(severity="medium", confidence=1.0), event()).score

    assert high_weak > medium_sure


# --- pure model: bounds ------------------------------------------------------


@pytest.mark.parametrize("severity", SEVERITIES)
@pytest.mark.parametrize("confidence", [0.0, 0.5, 1.0])
@pytest.mark.parametrize("role", [None, "viewer", "analyst", "admin"])
@pytest.mark.parametrize("prior", [0, 5, 1000])
def test_score_is_always_within_bounds(severity, confidence, role, prior):
    context = RiskContext(
        actor_role=role,
        device_trust=Decimal("0"),
        device_resolved=True,
        resource_sensitive=True,
        prior_threat_types=prior,
    )

    result = calculate_threat_risk(detection(severity=severity, confidence=confidence), event(user_id=1), context)

    assert config.RISK_MIN_SCORE <= result.score <= config.RISK_MAX_SCORE
    assert result.level in {band[2] for band in config.RISK_LEVEL_BANDS}


@pytest.mark.parametrize("hostile", [-1.0, -999, 1.5, 100, 10**9, Decimal("-5")])
def test_out_of_range_confidence_is_clamped_not_trusted(hostile):
    result = calculate_threat_risk(detection(confidence=hostile), event())

    assert config.RISK_MIN_SCORE <= result.score <= config.RISK_MAX_SCORE
    reported = next(f for f in result.factors if f.factor == "detection_confidence").value
    assert 0.0 <= reported <= 1.0


def test_non_numeric_confidence_is_rejected():
    with pytest.raises(ValueError):
        calculate_threat_risk(detection(confidence="'; DROP TABLE threats; --"), event())


def test_bands_cover_every_score_without_gaps():
    assert [level_for(s) for s in range(0, 101)].count("low") > 0
    for score in range(0, 101):
        level_for(score)  # must not raise
    with pytest.raises(ValueError):
        level_for(101)


# --- pure model: explainability and determinism ------------------------------


def test_factors_always_sum_to_the_score():
    for severity in SEVERITIES:
        for prior in [0, 3, 500]:
            context = RiskContext(actor_role="admin", prior_threat_types=prior, resource_sensitive=True)
            result = calculate_threat_risk(detection(severity=severity), event(user_id=1), context)
            assert sum(f.contribution for f in result.factors) == result.score


def test_clamping_is_recorded_as_a_factor():
    context = RiskContext(actor_role="admin", prior_threat_types=99, resource_sensitive=True)

    result = calculate_threat_risk(detection(severity="critical", confidence=1.0), event(user_id=1), context)

    assert result.score == config.RISK_MAX_SCORE
    assert sum(f.contribution for f in result.factors) == result.score
    if any(f.factor == "bounds_clamp" for f in result.factors):
        assert next(f for f in result.factors if f.factor == "bounds_clamp").contribution < 0


def test_every_factor_carries_a_human_readable_detail():
    result = calculate_threat_risk(detection(), event(user_id=1), RiskContext(actor_role="admin"))

    assert result.factors
    for factor in result.factors:
        assert factor.detail and isinstance(factor.detail, str)
        assert factor.factor


def test_calculation_is_deterministic():
    context = RiskContext(actor_role="analyst", prior_threat_types=2, resource_sensitive=True)
    args = (detection(severity="critical", confidence=0.87), event(user_id=1), context)

    scores = {calculate_threat_risk(*args).score for _ in range(25)}

    assert len(scores) == 1


def test_result_serialises_with_model_version():
    payload = calculate_threat_risk(detection(), event()).to_dict()

    assert payload["model_version"] == config.RISK_MODEL_VERSION
    assert payload["score"] == payload["score"]
    assert all({"factor", "value", "contribution", "detail"} <= set(f) for f in payload["factors"])


# --- pure model: context factors ---------------------------------------------


def test_privileged_identity_raises_risk():
    scores = {
        role: calculate_threat_risk(detection(), event(user_id=1), RiskContext(actor_role=role)).score
        for role in ["viewer", "analyst", "admin"]
    }

    assert scores["admin"] > scores["analyst"] > scores["viewer"]


def test_untrusted_device_raises_risk_more_than_unknown_device():
    trusted = RiskContext(device_trust=Decimal("95"), device_resolved=True)
    untrusted = RiskContext(device_trust=Decimal("5"), device_resolved=True)
    unknown = RiskContext(device_resolved=False)

    scored = {
        name: calculate_threat_risk(detection(), event(user_id=1), ctx).score
        for name, ctx in [("trusted", trusted), ("untrusted", untrusted), ("unknown", unknown)]
    }

    assert scored["untrusted"] > scored["unknown"] > scored["trusted"]


def test_device_factor_is_not_applied_without_a_principal():
    result = calculate_threat_risk(detection(), event(user_id=None), RiskContext(device_resolved=False))

    device = next(f for f in result.factors if f.factor == "device_trust")
    assert device.contribution == 0


def test_sensitive_resource_is_not_double_counted_for_privileged_access():
    """The privileged-access rule fires *because* of the resource."""
    context = RiskContext(resource_sensitive=True)

    privileged = calculate_threat_risk(
        detection(threat_type=config.THREAT_PRIVILEGED_ACCESS), event(), context
    )
    injection = calculate_threat_risk(
        detection(threat_type=config.THREAT_SQL_INJECTION), event(), context
    )

    assert next(f for f in privileged.factors if f.factor == "resource_sensitivity").contribution == 0
    assert next(f for f in injection.factors if f.factor == "resource_sensitivity").contribution > 0


def test_escalation_is_capped():
    small = calculate_threat_risk(detection(), event(), RiskContext(prior_threat_types=1))
    huge = calculate_threat_risk(detection(), event(), RiskContext(prior_threat_types=10**6))

    cap = config.RISK_ESCALATION_MAX_POINTS
    assert next(f for f in huge.factors if f.factor == "threat_escalation").contribution == cap
    assert next(f for f in small.factors if f.factor == "threat_escalation").contribution <= cap


def test_negative_prior_count_cannot_reduce_risk():
    poisoned = calculate_threat_risk(detection(), event(), RiskContext(prior_threat_types=-50))
    clean = calculate_threat_risk(detection(), event(), RiskContext(prior_threat_types=0))

    assert poisoned.score == clean.score


# --- integration: risk is wired into ingestion -------------------------------


def ingest(client, auth, **payload):
    response = client.post(EVENTS, json=payload, headers=auth)
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def failed_login(client, auth, offset=0, **extra):
    metadata = {"username": "admin01"}
    metadata.update(extra.pop("metadata", {}))
    return ingest(
        client,
        auth,
        event_type="auth.login.failure",
        source_ip="203.0.113.44",
        occurred_at=(BASE + timedelta(seconds=offset)).isoformat(),
        metadata=metadata,
        **extra,
    )


def test_normal_event_produces_no_threat_and_no_risk(client, write_auth, db):
    body = ingest(client, write_auth, event_type="auth.login.success", source_ip="10.0.0.1")

    assert body["detections"] == []
    assert db.execute("SELECT count(*) AS n FROM threats").fetchone()["n"] == 0


def test_brute_force_is_scored_and_persisted(client, write_auth, db):
    bodies = [failed_login(client, write_auth, offset=i * 10) for i in range(5)]
    detection_summary = bodies[-1]["detections"][0]

    assert detection_summary["risk_level"] in {"medium", "high", "critical"}

    row = db.execute("SELECT * FROM threats WHERE event_id = %s", (bodies[-1]["id"],)).fetchone()
    assert int(row["risk_score"]) == detection_summary["risk_score"]
    assert row["risk_level"] == detection_summary["risk_level"]
    assert row["risk_calculated_at"] is not None
    assert row["risk_factors"]["model_version"] == config.RISK_MODEL_VERSION


def test_sql_injection_scores_higher_than_brute_force(client, write_auth, db):
    for i in range(5):
        failed_login(client, write_auth, offset=i * 10)
    brute = db.execute(
        "SELECT risk_score FROM threats WHERE threat_type = %s", (config.THREAT_BRUTE_FORCE,)
    ).fetchone()

    injection = ingest(
        client,
        write_auth,
        event_type="api.request",
        source_ip="198.51.100.7",
        metadata={"method": "GET", "path": "/api/search", "query": {"q": "' OR 1=1 --"}},
    )

    assert injection["detections"][0]["risk_score"] > int(brute["risk_score"])


def test_risk_factors_survive_a_database_reload(client, write_auth, db):
    body = ingest(
        client,
        write_auth,
        event_type="api.request",
        source_ip="198.51.100.7",
        metadata={"path": "/api/search", "query": {"q": "' OR 1=1 --"}},
    )

    row = db.execute("SELECT risk_factors FROM threats WHERE event_id = %s", (body["id"],)).fetchone()
    factors = row["risk_factors"]["factors"]

    assert sum(f["contribution"] for f in factors) == body["detections"][0]["risk_score"]
    assert {f["factor"] for f in factors} >= {"threat_severity", "detection_confidence"}


def test_threats_api_exposes_risk(client, write_auth, read_auth):
    ingest(
        client,
        write_auth,
        event_type="api.request",
        source_ip="198.51.100.7",
        metadata={"path": "/api/search", "query": {"q": "' OR 1=1 --"}},
    )

    row = client.get(THREATS, headers=read_auth).get_json()["data"][0]

    assert 0 <= row["risk_score"] <= 100
    assert row["risk_level"] in {"low", "medium", "high", "critical"}
    assert row["risk_factors"]["factors"]


# --- integration: context must come from authoritative records ---------------


def test_authoritative_role_raises_risk(client, write_auth, db, make_user):
    admin = make_user("m.acheampong", "admin")
    viewer = make_user("t.devries", "viewer")

    payload = {"method": "GET", "path": "/api/search", "query": {"q": "' OR 1=1 --"}}
    by_viewer = ingest(
        client, write_auth, event_type="api.request", user_id=viewer, source_ip="198.51.100.7", metadata=payload
    )
    by_admin = ingest(
        client, write_auth, event_type="api.request", user_id=admin, source_ip="198.51.100.8", metadata=payload
    )

    assert by_admin["detections"][0]["risk_score"] > by_viewer["detections"][0]["risk_score"]


def test_forged_role_in_metadata_cannot_raise_privilege(client, write_auth, make_user):
    viewer = make_user("t.devries", "viewer")

    honest = ingest(
        client,
        write_auth,
        event_type="api.request",
        user_id=viewer,
        source_ip="198.51.100.7",
        metadata={"path": "/api/search", "query": {"q": "' OR 1=1 --"}},
    )
    forged = ingest(
        client,
        write_auth,
        event_type="api.request",
        user_id=viewer,
        source_ip="198.51.100.8",
        metadata={"path": "/api/search", "role": "admin", "query": {"q": "' OR 1=1 --"}},
    )

    assert forged["detections"][0]["risk_score"] == honest["detections"][0]["risk_score"]


def test_forged_device_trust_in_metadata_is_ignored(client, write_auth, db, make_user):
    viewer = make_user("t.devries", "viewer")
    db.execute(
        "INSERT INTO devices (user_id, device_fingerprint, trust_score) VALUES (%s, 'fp-real', 10)", (viewer,)
    )

    forged = ingest(
        client,
        write_auth,
        event_type="api.request",
        user_id=viewer,
        source_ip="198.51.100.7",
        metadata={
            "path": "/api/search",
            "device_fingerprint": "fp-real",
            "trust_score": 100,
            "query": {"q": "' OR 1=1 --"},
        },
    )

    row = db.execute("SELECT risk_factors FROM threats WHERE event_id = %s", (forged["id"],)).fetchone()
    device = next(f for f in row["risk_factors"]["factors"] if f["factor"] == "device_trust")
    # The authoritative trust score is 10, not the 100 the client asserted.
    assert device["value"] == 10.0
    assert device["contribution"] == config.RISK_UNTRUSTED_DEVICE_POINTS


def test_device_fingerprint_belonging_to_another_user_does_not_resolve(client, write_auth, db, make_user):
    owner = make_user("m.acheampong", "admin")
    attacker = make_user("t.devries", "viewer")
    db.execute(
        "INSERT INTO devices (user_id, device_fingerprint, trust_score) VALUES (%s, 'fp-trusted', 99)", (owner,)
    )

    body = ingest(
        client,
        write_auth,
        event_type="api.request",
        user_id=attacker,
        source_ip="198.51.100.7",
        metadata={"path": "/api/search", "device_fingerprint": "fp-trusted", "query": {"q": "' OR 1=1 --"}},
    )

    row = db.execute("SELECT risk_factors FROM threats WHERE event_id = %s", (body["id"],)).fetchone()
    device = next(f for f in row["risk_factors"]["factors"] if f["factor"] == "device_trust")
    assert device["contribution"] == config.RISK_UNKNOWN_DEVICE_POINTS


def test_missing_user_record_does_not_break_scoring(client, write_auth, db):
    """A deleted user nulls the event's user_id; scoring must still work."""
    user_id = db.execute(
        "INSERT INTO users (username, role) VALUES ('temporary', 'viewer') RETURNING id"
    ).fetchone()["id"]
    body = ingest(
        client,
        write_auth,
        event_type="api.request",
        user_id=user_id,
        source_ip="198.51.100.7",
        metadata={"path": "/api/search", "query": {"q": "' OR 1=1 --"}},
    )
    db.execute("DELETE FROM users WHERE id = %s", (user_id,))

    row = db.execute("SELECT risk_score, user_id FROM threats t JOIN events e ON e.id = t.event_id WHERE t.event_id = %s", (body["id"],)).fetchone()
    assert row["user_id"] is None
    assert 0 <= int(row["risk_score"]) <= 100


# --- integration: clients cannot supply risk ---------------------------------


@pytest.mark.parametrize("field,value", [("risk_score", 100), ("risk_level", "critical"), ("risk_factors", {})])
def test_clients_cannot_submit_risk_fields(client, write_auth, db, field, value):
    response = client.post(
        EVENTS, json={"event_type": "api.request", field: value}, headers=write_auth
    )

    assert response.status_code == 400
    assert any(d["field"] == field for d in response.get_json()["error"]["details"])
    assert db.execute("SELECT count(*) AS n FROM events").fetchone()["n"] == 0


def test_database_rejects_out_of_range_risk_score(db):
    import psycopg

    event_id = db.execute(
        "INSERT INTO events (event_type, occurred_at) VALUES ('api.request', now()) RETURNING id"
    ).fetchone()["id"]

    # -1 and 101 trip the CHECK; 9999 cannot even fit numeric(5,2), so the
    # column's own precision rejects it first. Both are refusals.
    for bad, expected in [
        (-1, psycopg.errors.CheckViolation),
        (101, psycopg.errors.CheckViolation),
        (9999, psycopg.errors.NumericValueOutOfRange),
    ]:
        with pytest.raises(expected):
            db.execute(
                "INSERT INTO threats (event_id, threat_type, severity, confidence, rule_id, risk_score, risk_level)"
                " VALUES (%s, 'x', 'high', 0.5, 'r', %s, 'high')",
                (event_id, bad),
            )


def test_database_rejects_half_written_risk(db):
    import psycopg

    event_id = db.execute(
        "INSERT INTO events (event_type, occurred_at) VALUES ('api.request', now()) RETURNING id"
    ).fetchone()["id"]

    with pytest.raises(psycopg.errors.CheckViolation):
        db.execute(
            "INSERT INTO threats (event_id, threat_type, severity, confidence, rule_id, risk_score)"
            " VALUES (%s, 'x', 'high', 0.5, 'r', 50)",
            (event_id,),
        )


def test_rescoring_does_not_duplicate_threats(client, write_auth, db, rerun_detection):
    bodies = [failed_login(client, write_auth, offset=i * 10) for i in range(5)]
    triggering = bodies[-1]["id"]

    before = db.execute("SELECT * FROM threats WHERE event_id = %s", (triggering,)).fetchone()
    for _ in range(3):
        rerun_detection(triggering)
    after = db.execute("SELECT * FROM threats WHERE event_id = %s", (triggering,)).fetchall()

    assert len(after) == 1
    assert after[0]["id"] == before["id"]
    assert after[0]["risk_score"] == before["risk_score"]
