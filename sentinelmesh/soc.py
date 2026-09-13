"""SOC dashboard backend-for-frontend.

The browser never holds a service credential. An operator signs in with an
existing read-scoped API key, and Flask keeps the resulting principal in a
signed, HttpOnly, SameSite=Strict cookie. JavaScript cannot read it, it is not
in the bundle, and nothing is written to localStorage.

The session is a browser transport for the *existing* scoped-credential design,
not a second authentication system: it grants exactly the scopes the credential
already had, and the dashboard only ever needs `read`.
"""

import hmac
import logging

from flask import Blueprint, current_app, jsonify, request, session

from . import config
from .auth import require_scope
from .db import connection
from .errors import ApiError
from .responses import serialise as serialise_response
from .threats import _serialise as serialise_threat

bp = Blueprint("soc", __name__)
log = logging.getLogger("sentinelmesh.soc")

SESSION_KEY = "api_key_name"

# Counts are computed by PostgreSQL with FILTER clauses in a single pass rather
# than by fetching incidents and counting them in Python.
SUMMARY_SQL = """
    SELECT
        count(*) FILTER (WHERE status = ANY (%(active)s::incident_status[]))                        AS active_incidents,
        count(*) FILTER (WHERE status = ANY (%(active)s::incident_status[]) AND risk_score >= %(crit)s) AS critical_incidents,
        count(*) FILTER (WHERE status = ANY (%(active)s::incident_status[])
                          AND risk_score >= %(high)s AND risk_score < %(crit)s)                     AS high_incidents,
        count(*) FILTER (WHERE status = ANY (%(active)s::incident_status[])
                          AND risk_score < %(high)s)                                                AS other_incidents,
        count(*)                                                                                    AS total_incidents
    FROM incidents
"""

CONTAINMENT_SQL = """
    SELECT
        (SELECT count(*) FROM users   WHERE contained) AS contained_subjects,
        (SELECT count(*) FROM devices WHERE isolated)  AS isolated_devices,
        (SELECT count(*) FROM blocked_sources)         AS blocked_sources
"""

RECENT_THREATS_SQL = """
    SELECT id, event_id, threat_type, severity, confidence, rule_id, evidence, detected_at,
           incident_id, risk_score, risk_level, risk_factors, risk_calculated_at
    FROM threats
    ORDER BY id DESC
    LIMIT %(limit)s
"""

RECENT_RESPONSES_SQL = """
    SELECT id, incident_id, threat_id, action, result, policy, reason, evidence, actor, occurred_at
    FROM responses
    ORDER BY id DESC
    LIMIT %(limit)s
"""

RECENT_DECISIONS_SQL = """
    SELECT id, decided_at, subject_username, resource, sensitivity, decision, policy, reason
    FROM access_decisions
    ORDER BY id DESC
    LIMIT %(limit)s
"""


# --- session -----------------------------------------------------------------


def _match_credential(presented: str):
    matched = None
    for key in current_app.config["API_KEYS"]:
        if hmac.compare_digest(key.secret, presented):
            matched = key
    return matched


@bp.post("/soc/login")
def login():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise ApiError(400, "validation_error", "The request body must be a JSON object.")

    credential = payload.get("credential")
    if not isinstance(credential, str) or not credential.strip():
        raise ApiError(400, "validation_error", "A credential is required.")

    key = _match_credential(credential.strip())
    if key is None or config.READ not in key.scopes:
        # Identical response either way: a caller must not learn whether a valid
        # credential merely lacked the scope.
        log.info("soc sign-in rejected", extra={"remote_addr": request.remote_addr})
        raise ApiError(401, "unauthenticated", "Invalid credentials.")

    session.clear()
    session[SESSION_KEY] = key.name
    session.permanent = False
    log.info("soc sign-in", extra={"api_key": key.name, "remote_addr": request.remote_addr})
    return jsonify({"operator": key.name, "scopes": sorted(key.scopes)})


@bp.post("/soc/logout")
def logout():
    session.clear()
    return jsonify({"signed_out": True})


@bp.get("/soc/session")
def whoami():
    name = session.get(SESSION_KEY)
    key = next((k for k in current_app.config["API_KEYS"] if k.name == name), None) if name else None
    if key is None:
        return jsonify({"authenticated": False}), 200
    return jsonify({"authenticated": True, "operator": key.name, "scopes": sorted(key.scopes)})


# --- summary -----------------------------------------------------------------


@bp.get("/api/soc/summary/")
@require_scope(config.READ)
def summary():
    """Everything the overview needs, in four aggregate queries."""
    conn = connection()
    params = {
        "active": list(config.ZT_ACTIVE_INCIDENT_STATUSES),
        "crit": config.ZT_CRITICAL_RISK,
        "high": config.ZT_HIGH_RISK,
    }

    with conn.cursor() as cur:
        cur.execute(SUMMARY_SQL, params)
        counts = cur.fetchone()
    with conn.cursor() as cur:
        cur.execute(CONTAINMENT_SQL)
        containment = cur.fetchone()
    with conn.cursor() as cur:
        cur.execute(RECENT_THREATS_SQL, {"limit": 8})
        threats = cur.fetchall()
    with conn.cursor() as cur:
        cur.execute(RECENT_RESPONSES_SQL, {"limit": 8})
        responses = cur.fetchall()
    with conn.cursor() as cur:
        cur.execute(RECENT_DECISIONS_SQL, {"limit": 6})
        decisions = cur.fetchall()

    return jsonify(
        {
            "incidents": {
                "active": counts["active_incidents"],
                "critical": counts["critical_incidents"],
                "high": counts["high_incidents"],
                "other": counts["other_incidents"],
                "total": counts["total_incidents"],
            },
            "containment": {
                "contained_subjects": containment["contained_subjects"],
                "isolated_devices": containment["isolated_devices"],
                "blocked_sources": containment["blocked_sources"],
            },
            "recent_threats": [serialise_threat(row) for row in threats],
            "recent_responses": [serialise_response(row) for row in responses],
            "recent_decisions": [
                {
                    "id": d["id"],
                    "decided_at": d["decided_at"].isoformat(),
                    "subject": d["subject_username"],
                    "resource": d["resource"],
                    "sensitivity": d["sensitivity"],
                    "decision": d["decision"],
                    "policy": d["policy"],
                    "reason": d["reason"],
                }
                for d in decisions
            ],
        }
    )
