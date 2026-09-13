"""Correlation and incident engine tests.

Pure decision functions (link scoring, classification, incident risk) are
exercised without a database; the rest drives real ingestion and asserts on
what PostgreSQL holds afterwards.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from sentinelmesh import config
from sentinelmesh.correlation import (
    calculate_incident_risk,
    classify,
    correlation_key_for,
    describe,
    score_link,
)

EVENTS = "/api/events/"
INCIDENTS = "/api/incidents/"
BASE = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

BRUTE = config.THREAT_BRUTE_FORCE
PRIV = config.THREAT_PRIVILEGED_ACCESS
SQLI = config.THREAT_SQL_INJECTION


def member(threat_type, seconds=0, risk=60, user_id=None):
    at = BASE + timedelta(seconds=seconds)
    return {
        "threat_type": threat_type,
        "occurred_at": at,
        "detected_at": at,
        "risk_score": risk,
        "user_id": user_id,
        "id": seconds,
    }


# --- pure: campaign identity -------------------------------------------------


def test_source_address_keys_the_campaign():
    assert correlation_key_for({"id": 1, "source_ip": "203.0.113.44", "user_id": 7}) == "ip:203.0.113.44"


def test_identity_keys_the_campaign_when_there_is_no_address():
    assert correlation_key_for({"id": 1, "source_ip": None, "user_id": 7}) == "user:7"


def test_event_without_address_or_identity_is_its_own_campaign():
    assert correlation_key_for({"id": 9, "source_ip": None, "user_id": None}) == "threat:event-9"


# --- pure: classification ----------------------------------------------------


def test_single_stage_campaigns_are_classified_by_stage():
    assert classify([member(BRUTE), member(BRUTE, 10)])[0] == config.CLASSIFICATION_CREDENTIAL
    assert classify([member(PRIV)])[0] == config.CLASSIFICATION_PRIVILEGE
    assert classify([member(SQLI)])[0] == config.CLASSIFICATION_APPLICATION


def test_ordered_stages_are_a_multi_stage_attack():
    classification, stages, ordered = classify([member(BRUTE, 0), member(PRIV, 60), member(SQLI, 120)])

    assert classification == config.CLASSIFICATION_MULTI_STAGE
    assert stages == ["Credential Abuse", "Privileged Access Attempt", "Application Injection"]
    assert ordered


def test_repeated_detections_of_one_type_are_not_multi_stage():
    """Three simultaneous injections are one stage, not a progression."""
    classification, _stages, _ = classify([member(SQLI, 0), member(SQLI, 0), member(SQLI, 0)])

    assert classification == config.CLASSIFICATION_APPLICATION


def test_out_of_order_stages_are_not_a_progression():
    # Injection first, credential abuse afterwards: not a campaign progressing.
    classification, _stages, ordered = classify([member(SQLI, 0), member(BRUTE, 60)])

    assert not ordered
    assert classification != config.CLASSIFICATION_MULTI_STAGE


def test_unknown_threat_types_are_unclassified():
    assert classify([member("something.unmapped")])[0] == config.CLASSIFICATION_UNCLASSIFIED
    assert classify([])[0] == config.CLASSIFICATION_UNCLASSIFIED


# --- pure: incident risk -----------------------------------------------------


def test_worst_threat_is_never_diluted_by_averaging():
    members = [member(BRUTE, 0, risk=60), member(BRUTE, 10, risk=60), member(SQLI, 20, risk=90)]

    score, _level, factors = calculate_incident_risk(members, config.CLASSIFICATION_APPLICATION, Decimal("0.5"))

    assert score >= 90, "a 90 must not be averaged down by two 60s"
    assert next(f for f in factors if f.factor == "highest_threat_risk").contribution == 90


def test_incident_risk_is_never_a_sum():
    members = [member(SQLI, i, risk=60) for i in range(5)]

    score, _level, _factors = calculate_incident_risk(members, config.CLASSIFICATION_APPLICATION, None)

    assert score < 300
    assert score <= config.RISK_MAX_SCORE


@pytest.mark.parametrize("risks", [[0], [100], [1, 100], [50, 50, 50], [100, 100, 100]])
@pytest.mark.parametrize("classification", [config.CLASSIFICATION_MULTI_STAGE, config.CLASSIFICATION_CREDENTIAL])
@pytest.mark.parametrize("confidence", [None, Decimal("0.05"), Decimal("0.99")])
def test_incident_risk_is_bounded(risks, classification, confidence):
    members = [member(SQLI, i, risk=r) for i, r in enumerate(risks)]

    score, level, factors = calculate_incident_risk(members, classification, confidence)

    assert config.RISK_MIN_SCORE <= score <= config.RISK_MAX_SCORE
    assert level in {b[2] for b in config.RISK_LEVEL_BANDS}
    assert sum(f.contribution for f in factors) == score


def test_incident_risk_factors_sum_to_the_score():
    members = [member(BRUTE, 0, risk=64), member(PRIV, 60, risk=72), member(SQLI, 120, risk=84)]

    score, _level, factors = calculate_incident_risk(members, config.CLASSIFICATION_MULTI_STAGE, Decimal("0.9"))

    assert sum(f.contribution for f in factors) == score


def test_identity_and_resource_are_not_double_counted_at_incident_level():
    members = [member(PRIV, 0, risk=72)]

    _score, _level, factors = calculate_incident_risk(members, config.CLASSIFICATION_PRIVILEGE, Decimal("0.9"))

    for name in ["privileged_identity", "resource_sensitivity"]:
        factor = next(f for f in factors if f.factor == name)
        assert factor.contribution == 0
        assert "not counted twice" in factor.detail


def test_multi_stage_and_breadth_raise_incident_risk():
    single = calculate_incident_risk([member(BRUTE, 0, risk=64)], config.CLASSIFICATION_CREDENTIAL, None)[0]
    campaign = calculate_incident_risk(
        [member(BRUTE, 0, risk=64), member(PRIV, 60, risk=64), member(SQLI, 120, risk=64)],
        config.CLASSIFICATION_MULTI_STAGE,
        Decimal("0.9"),
    )[0]

    assert campaign > single


def test_incident_risk_is_deterministic():
    members = [member(BRUTE, 0, risk=64), member(SQLI, 30, risk=84)]

    scores = {calculate_incident_risk(members, config.CLASSIFICATION_MULTI_STAGE, Decimal("0.8"))[0] for _ in range(20)}

    assert len(scores) == 1


# --- pure: link scoring ------------------------------------------------------


def incident(seconds=0, confidence=None):
    return {
        "id": 1,
        "correlation_key": "ip:203.0.113.44",
        "last_activity_at": BASE + timedelta(seconds=seconds),
        "correlation_confidence": confidence,
    }


def link_event(seconds=0, user_id=None, ip="203.0.113.44"):
    return {"id": 2, "source_ip": ip, "user_id": user_id, "occurred_at": BASE + timedelta(seconds=seconds)}


def test_closer_in_time_means_stronger_correlation():
    near = score_link(incident(), [member(BRUTE)], link_event(10), {"threat_type": SQLI})
    far = score_link(incident(), [member(BRUTE)], link_event(1700), {"threat_type": SQLI})

    assert near.confidence > far.confidence


def test_progression_to_a_new_stage_strengthens_correlation():
    progressing = score_link(incident(), [member(BRUTE)], link_event(10), {"threat_type": SQLI})
    repeating = score_link(incident(), [member(BRUTE)], link_event(10), {"threat_type": BRUTE})

    assert progressing.confidence > repeating.confidence


def test_same_user_strengthens_correlation():
    shared = score_link(incident(), [member(BRUTE, user_id=7)], link_event(10, user_id=7), {"threat_type": SQLI})
    unrelated = score_link(incident(), [member(BRUTE, user_id=7)], link_event(10, user_id=9), {"threat_type": SQLI})

    assert shared.confidence > unrelated.confidence


def test_correlation_confidence_stays_in_range():
    for seconds in [0, 100, 1799, 5000]:
        link = score_link(incident(), [member(BRUTE)], link_event(seconds), {"threat_type": SQLI})
        assert config.CORRELATION_CONFIDENCE_MIN <= link.confidence <= config.CORRELATION_CONFIDENCE_MAX


def test_correlation_confidence_is_not_detection_confidence():
    """A rule can be 0.95 sure while the campaign link is much weaker."""
    link = score_link(incident(), [member(BRUTE)], link_event(1500), {"threat_type": BRUTE})

    assert link.confidence < Decimal("0.95")


def test_link_signals_are_explainable():
    link = score_link(incident(), [member(BRUTE)], link_event(10), {"threat_type": SQLI})

    names = {s["factor"] for s in link.to_list()}
    assert names == {"same_source", "same_user", "temporal_proximity", "attack_progression"}
    for signal in link.to_list():
        assert signal["detail"]


def test_description_is_human_readable():
    text = describe(
        [member(BRUTE, 0), member(PRIV, 60), member(SQLI, 96)],
        config.CLASSIFICATION_MULTI_STAGE,
        ["Credential Abuse", "Privileged Access Attempt", "Application Injection"],
        Decimal("0.91"),
        "ip:203.0.113.44",
    )

    assert "203.0.113.44" in text
    assert "96 seconds" in text
    assert "progressed from" in text
    assert "HIGH" in text


# --- integration helpers -----------------------------------------------------


def ingest(client, auth, **payload):
    response = client.post(EVENTS, json=payload, headers=auth)
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def brute_force_campaign(client, auth, ip="203.0.113.44", start=0, count=5):
    bodies = []
    for i in range(count):
        bodies.append(
            ingest(
                client,
                auth,
                event_type="auth.login.failure",
                source_ip=ip,
                occurred_at=(BASE + timedelta(seconds=start + i * 10)).isoformat(),
                metadata={"username": "admin01", "attempt": i},
            )
        )
    return bodies


def privileged_attempt(client, auth, user_id, ip="203.0.113.44", offset=200):
    return ingest(
        client,
        auth,
        event_type="api.request",
        user_id=user_id,
        source_ip=ip,
        occurred_at=(BASE + timedelta(seconds=offset)).isoformat(),
        metadata={"method": "GET", "path": "/api/admin/users"},
    )


def injection(client, auth, ip="203.0.113.44", offset=300, user_id=None):
    payload = {"event_type": "api.request", "source_ip": ip, "metadata": {"path": "/api/search", "query": {"q": "' OR 1=1 --"}}}
    if user_id is not None:
        payload["user_id"] = user_id
    payload["occurred_at"] = (BASE + timedelta(seconds=offset)).isoformat()
    return ingest(client, auth, **payload)


def incidents_in(db):
    return db.execute("SELECT * FROM incidents ORDER BY id").fetchall()


# --- integration: grouping ---------------------------------------------------


def test_brute_force_campaign_produces_one_incident(client, write_auth, db):
    """Seven failures past the threshold must not become seven incidents."""
    brute_force_campaign(client, write_auth, count=11)

    threats = db.execute("SELECT count(*) AS n FROM threats").fetchone()["n"]
    rows = incidents_in(db)

    assert threats == 7, "failures 5..11 each trip the rule"
    assert len(rows) == 1
    assert rows[0]["classification"] == config.CLASSIFICATION_CREDENTIAL
    assert db.execute(
        "SELECT count(*) AS n FROM threats WHERE incident_id = %s", (rows[0]["id"],)
    ).fetchone()["n"] == 7


def test_same_source_threats_correlate(client, write_auth, db, make_user):
    viewer = make_user("t.devries", "viewer")
    brute_force_campaign(client, write_auth)
    privileged_attempt(client, write_auth, viewer)

    rows = incidents_in(db)
    assert len(rows) == 1
    assert rows[0]["correlation_key"] == "ip:203.0.113.44"


def test_different_sources_stay_separate(client, write_auth, db):
    brute_force_campaign(client, write_auth, ip="203.0.113.44")
    brute_force_campaign(client, write_auth, ip="198.51.100.7")

    rows = incidents_in(db)
    assert len(rows) == 2
    assert {r["correlation_key"] for r in rows} == {"ip:203.0.113.44", "ip:198.51.100.7"}


def test_threats_outside_the_window_start_a_new_incident(client, write_auth, db):
    brute_force_campaign(client, write_auth, start=0)
    # Well beyond the 1800s window measured from the last activity.
    brute_force_campaign(client, write_auth, start=config.CORRELATION_WINDOW_SECONDS + 600)

    rows = incidents_in(db)
    assert len(rows) == 2
    # The lapsed incident stops accumulating but is NOT closed.
    assert [r["correlating"] for r in rows] == [False, True]
    assert [r["status"] for r in rows] == ["open", "open"]


def test_threats_inside_the_window_join_the_same_incident(client, write_auth, db):
    brute_force_campaign(client, write_auth, start=0)
    brute_force_campaign(client, write_auth, start=config.CORRELATION_WINDOW_SECONDS - 600)

    assert len(incidents_in(db)) == 1


def test_unrelated_attacks_remain_separate(client, write_auth, db, make_user):
    viewer = make_user("t.devries", "viewer")
    admin = make_user("m.acheampong", "admin")

    brute_force_campaign(client, write_auth, ip="203.0.113.44")
    privileged_attempt(client, write_auth, viewer, ip="198.51.100.7", offset=50)
    injection(client, write_auth, ip="192.0.2.9", offset=80, user_id=admin)

    rows = incidents_in(db)
    assert len(rows) == 3
    assert len({r["correlation_key"] for r in rows}) == 3


# --- integration: the multi-stage campaign -----------------------------------


@pytest.fixture
def multi_stage(client, write_auth, db, make_user):
    viewer = make_user("t.devries", "viewer")
    brute_force_campaign(client, write_auth)
    privileged_attempt(client, write_auth, viewer, offset=200)
    injection(client, write_auth, offset=300)
    return incidents_in(db)[0]


def test_multi_stage_attack_is_one_classified_incident(multi_stage, db):
    assert multi_stage["classification"] == config.CLASSIFICATION_MULTI_STAGE
    assert len(incidents_in(db)) == 1

    members = db.execute(
        "SELECT DISTINCT threat_type FROM threats WHERE incident_id = %s", (multi_stage["id"],)
    ).fetchall()
    assert {m["threat_type"] for m in members} == {BRUTE, PRIV, SQLI}


def test_multi_stage_incident_is_explainable(multi_stage):
    factors = multi_stage["correlation_factors"]

    assert factors["model_version"] == config.CORRELATION_MODEL_VERSION
    assert factors["attack_stages"] == [
        "Credential Abuse",
        "Privileged Access Attempt",
        "Application Injection",
    ]
    assert "progressed from" in factors["explanation"]
    assert factors["signals"], "the strongest correlation link must be retained"


def test_multi_stage_incident_risk_is_explainable(multi_stage):
    risk = multi_stage["risk_factors"]

    assert sum(f["contribution"] for f in risk["factors"]) == int(multi_stage["risk_score"])
    assert 0 <= int(multi_stage["risk_score"]) <= 100
    progression = next(f for f in risk["factors"] if f["factor"] == "attack_progression")
    assert progression["contribution"] == config.INCIDENT_PROGRESSION_POINTS


def test_incident_risk_is_at_least_its_worst_threat(multi_stage, db):
    worst = db.execute(
        "SELECT max(risk_score) AS m FROM threats WHERE incident_id = %s", (multi_stage["id"],)
    ).fetchone()["m"]

    assert int(multi_stage["risk_score"]) >= int(worst)


def test_incident_severity_matches_its_risk_band(multi_stage):
    from sentinelmesh.risk import level_for

    assert multi_stage["severity"] == level_for(int(multi_stage["risk_score"]))


def test_incident_stays_open(multi_stage):
    assert multi_stage["status"] == "open"
    assert multi_stage["correlating"] is True


# --- integration: idempotency and duplicates ---------------------------------


def test_reprocessing_threats_creates_no_duplicate_incident(client, write_auth, db, rerun_detection):
    bodies = brute_force_campaign(client, write_auth)
    triggering = bodies[-1]["id"]
    before = incidents_in(db)

    for _ in range(3):
        rerun_detection(triggering)

    after = incidents_in(db)
    assert len(after) == len(before) == 1
    assert after[0]["id"] == before[0]["id"]
    assert db.execute("SELECT count(*) AS n FROM threats").fetchone()["n"] == 1


def test_reprocessing_does_not_move_a_threat_between_incidents(client, write_auth, db, rerun_detection):
    bodies = brute_force_campaign(client, write_auth)
    triggering = bodies[-1]["id"]
    original = db.execute("SELECT incident_id FROM threats WHERE event_id = %s", (triggering,)).fetchone()

    rerun_detection(triggering)

    assert db.execute(
        "SELECT incident_id FROM threats WHERE event_id = %s", (triggering,)
    ).fetchone()["incident_id"] == original["incident_id"]


def test_unique_index_forbids_two_correlating_incidents_per_key(db):
    import psycopg

    db.execute(
        "INSERT INTO incidents (title, severity, risk_score, correlation_key, classification, last_activity_at)"
        " VALUES ('a', 'low', 10, 'ip:203.0.113.44', 'credential_attack', now())"
    )
    with pytest.raises(psycopg.errors.UniqueViolation):
        db.execute(
            "INSERT INTO incidents (title, severity, risk_score, correlation_key, classification, last_activity_at)"
            " VALUES ('b', 'low', 10, 'ip:203.0.113.44', 'credential_attack', now())"
        )


def test_retired_incident_frees_the_key(db):
    db.execute(
        "INSERT INTO incidents (title, severity, risk_score, correlation_key, classification, last_activity_at,"
        " correlating) VALUES ('a', 'low', 10, 'ip:203.0.113.44', 'credential_attack', now(), false)"
    )
    db.execute(
        "INSERT INTO incidents (title, severity, risk_score, correlation_key, classification, last_activity_at)"
        " VALUES ('b', 'low', 10, 'ip:203.0.113.44', 'credential_attack', now())"
    )

    assert db.execute("SELECT count(*) AS n FROM incidents").fetchone()["n"] == 2


def test_concurrent_related_ingest_produces_one_incident(app, db, make_user):
    """Two simultaneous ingests for the same campaign must not both create."""
    import threading

    make_user("t.devries", "viewer")
    barrier = threading.Barrier(2)
    errors = []

    def submit(offset):
        try:
            client = app.test_client()
            barrier.wait(timeout=10)
            client.post(
                EVENTS,
                json={
                    "event_type": "api.request",
                    "source_ip": "203.0.113.44",
                    "occurred_at": (BASE + timedelta(seconds=offset)).isoformat(),
                    "metadata": {"path": "/api/search", "query": {"q": "' OR 1=1 --"}},
                },
                headers={"Authorization": "Bearer test-write-secret-000000"},
            )
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            errors.append(exc)

    threads = [threading.Thread(target=submit, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    assert not errors, errors
    rows = incidents_in(db)
    assert len(rows) == 1, f"expected one incident, got {[r['correlation_key'] for r in rows]}"
    assert db.execute("SELECT count(*) AS n FROM threats WHERE incident_id IS NOT NULL").fetchone()["n"] == 2


# --- integration: persistence and API ----------------------------------------


def test_incident_survives_a_database_reload(multi_stage, db):
    reloaded = db.execute("SELECT * FROM incidents WHERE id = %s", (multi_stage["id"],)).fetchone()

    assert reloaded["classification"] == config.CLASSIFICATION_MULTI_STAGE
    assert reloaded["risk_score"] == multi_stage["risk_score"]
    assert reloaded["correlation_confidence"] == multi_stage["correlation_confidence"]
    assert reloaded["correlation_factors"]["explanation"]
    assert reloaded["risk_factors"]["factors"]
    assert db.execute(
        "SELECT count(*) AS n FROM threats WHERE incident_id = %s", (reloaded["id"],)
    ).fetchone()["n"] == 3


def test_incident_api_requires_read_scope(client, write_auth):
    assert client.get(INCIDENTS).status_code == 401
    assert client.get(INCIDENTS, headers=write_auth).status_code == 403


def test_incident_list_endpoint(multi_stage, client, read_auth):
    data = client.get(INCIDENTS, headers=read_auth).get_json()["data"]

    assert len(data) == 1
    assert data[0]["classification"] == config.CLASSIFICATION_MULTI_STAGE
    assert data[0]["threat_count"] == 3
    assert data[0]["reference"] == f"SM-{multi_stage['id']:03d}"
    assert 0 <= data[0]["risk_score"] <= 100


def test_incident_detail_endpoint_carries_threats_and_timeline(multi_stage, client, read_auth):
    body = client.get(f"{INCIDENTS}{multi_stage['id']}", headers=read_auth).get_json()

    assert len(body["threats"]) == 3
    assert {t["threat_type"] for t in body["threats"]} == {BRUTE, PRIV, SQLI}
    assert body["timeline"], "timeline must be derived"
    assert body["timeline"] == sorted(body["timeline"], key=lambda e: (e["at"], e["kind"]))
    assert body["correlation_confidence"] is not None
    assert body["risk_factors"]["factors"]


def test_incident_detail_404(client, read_auth):
    assert client.get(f"{INCIDENTS}999999", headers=read_auth).status_code == 404


def test_incidents_can_be_filtered_by_status(multi_stage, client, read_auth):
    assert len(client.get(f"{INCIDENTS}?status=open", headers=read_auth).get_json()["data"]) == 1
    assert client.get(f"{INCIDENTS}?status=resolved", headers=read_auth).get_json()["data"] == []
    assert client.get(f"{INCIDENTS}?status=nonsense", headers=read_auth).status_code == 400


# --- security ----------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("incident_id", 1),
        ("correlation_confidence", 1),
        ("correlation_key", "ip:evil"),
        ("classification", "multi_stage_attack"),
        ("risk_score", 100),
        ("severity", "critical"),
    ],
)
def test_clients_cannot_influence_correlation_through_ingestion(client, write_auth, db, field, value):
    response = client.post(EVENTS, json={"event_type": "api.request", field: value}, headers=write_auth)

    assert response.status_code == 400
    assert any(d["field"] == field for d in response.get_json()["error"]["details"])
    assert db.execute("SELECT count(*) AS n FROM incidents").fetchone()["n"] == 0


def test_forged_metadata_cannot_redirect_membership(client, write_auth, db):
    """Metadata claiming an incident must not change which incident is used."""
    brute_force_campaign(client, write_auth)
    real = incidents_in(db)[0]["id"]

    injection(client, write_auth, offset=310)

    rows = db.execute("SELECT DISTINCT incident_id FROM threats WHERE incident_id IS NOT NULL").fetchall()
    assert [r["incident_id"] for r in rows] == [real]


def test_correlation_uses_authoritative_source_not_metadata(client, write_auth, db):
    """A spoofed source_ip inside metadata does not key the campaign."""
    brute_force_campaign(client, write_auth, ip="203.0.113.44")
    ingest(
        client,
        write_auth,
        event_type="api.request",
        source_ip="198.51.100.7",
        occurred_at=(BASE + timedelta(seconds=310)).isoformat(),
        metadata={"path": "/api/search", "source_ip": "203.0.113.44", "query": {"q": "' OR 1=1 --"}},
    )

    rows = incidents_in(db)
    assert len(rows) == 2
    assert {r["correlation_key"] for r in rows} == {"ip:203.0.113.44", "ip:198.51.100.7"}
