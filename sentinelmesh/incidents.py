from flask import Blueprint, g, jsonify, request

from . import config
from .auth import require_scope
from .correlation import build_timeline
from .db import connection
from .errors import ApiError
from .response import respond_to_incident
from .responses import COLUMNS as response_columns
from .responses import serialise as serialise_response

bp = Blueprint("incidents", __name__, url_prefix="/api/incidents")

COLUMNS = (
    "id, title, classification, status, severity, risk_score, risk_factors, "
    "correlation_key, correlation_confidence, correlation_factors, correlating, "
    "created_at, last_activity_at"
)

LIST_SQL = f"""
    SELECT {COLUMNS},
           (SELECT count(*) FROM threats t WHERE t.incident_id = i.id) AS threat_count
    FROM incidents i
    WHERE (%(cursor_id)s::bigint IS NULL OR id < %(cursor_id)s::bigint)
      AND (%(status)s::incident_status IS NULL OR status = %(status)s::incident_status)
    ORDER BY id DESC
    LIMIT %(limit)s
"""

THREATS_SQL = """
    SELECT t.id, t.threat_type, t.severity, t.confidence, t.rule_id,
           t.risk_score, t.risk_level, t.risk_factors, t.detected_at, t.evidence,
           e.id AS event_id, e.event_type, e.source_ip, e.user_id, e.occurred_at
    FROM threats t
    JOIN events e ON e.id = t.event_id
    WHERE t.incident_id = %s
    ORDER BY t.detected_at, t.id
"""


DECISIONS_FOR_INCIDENT_SQL = """
    SELECT id, decided_at, subject_username, subject_role, device_state,
           resource, sensitivity, decision, policy, reason, factors
    FROM access_decisions
    WHERE incident_id = %s
    ORDER BY id DESC
    LIMIT 10
"""

INCIDENT_SUBJECTS_SQL = """
    SELECT DISTINCT u.id, u.username, u.role, u.contained
    FROM threats t
    JOIN events e ON e.id = t.event_id
    JOIN users u ON u.id = e.user_id
    WHERE t.incident_id = %s
"""

INCIDENT_SOURCES_SQL = """
    SELECT DISTINCT host(e.source_ip) AS source_ip, (b.source_ip IS NOT NULL) AS blocked
    FROM threats t
    JOIN events e ON e.id = t.event_id
    LEFT JOIN blocked_sources b ON b.source_ip = e.source_ip
    WHERE t.incident_id = %s AND e.source_ip IS NOT NULL
"""

INCIDENT_DEVICES_SQL = """
    SELECT DISTINCT d.id, d.device_fingerprint, d.isolated, d.trust_score
    FROM devices d
    JOIN events e ON e.user_id = d.user_id
                 AND e.metadata ->> 'device_fingerprint' = d.device_fingerprint
    JOIN threats t ON t.event_id = e.id
    WHERE t.incident_id = %s
"""


def reference(incident_id: int) -> str:
    """Operator-facing label. Derived from the id rather than stored."""
    return f"SM-{incident_id:03d}"


def _serialise(row: dict, threat_count: int) -> dict:
    return {
        "id": row["id"],
        "reference": reference(row["id"]),
        "title": row["title"],
        "classification": row["classification"],
        "status": row["status"],
        "severity": row["severity"],
        "risk_score": int(row["risk_score"]),
        "risk_factors": row["risk_factors"],
        "correlation_key": row["correlation_key"],
        "correlation_confidence": (
            float(row["correlation_confidence"]) if row["correlation_confidence"] is not None else None
        ),
        "correlation_factors": row["correlation_factors"],
        "correlating": row["correlating"],
        "threat_count": threat_count,
        "created_at": row["created_at"].isoformat(),
        "last_activity_at": row["last_activity_at"].isoformat(),
    }


def _serialise_threat(row: dict) -> dict:
    return {
        "id": row["id"],
        "threat_type": row["threat_type"],
        "severity": row["severity"],
        "confidence": float(row["confidence"]),
        "rule_id": row["rule_id"],
        "risk_score": int(row["risk_score"]) if row["risk_score"] is not None else None,
        "risk_level": row["risk_level"],
        # The Phase 3 factor breakdown, so the dashboard can show why this
        # threat scored what it did without recomputing anything.
        "risk_factors": row["risk_factors"],
        "detected_at": row["detected_at"].isoformat(),
        "reason": row["evidence"].get("reason") if isinstance(row["evidence"], dict) else None,
        "event": {
            "id": row["event_id"],
            "event_type": row["event_type"],
            "source_ip": str(row["source_ip"]) if row["source_ip"] is not None else None,
            "user_id": row["user_id"],
            "occurred_at": row["occurred_at"].isoformat(),
        },
    }


def _int_param(name: str, default=None):
    raw = request.args.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ApiError(400, "validation_error", f"{name} must be an integer.") from None


@bp.get("/")
@require_scope(config.READ)
def list_incidents():
    limit = _int_param("limit", config.DEFAULT_PAGE_SIZE)
    if not 1 <= limit <= config.MAX_PAGE_SIZE:
        raise ApiError(400, "validation_error", f"limit must be between 1 and {config.MAX_PAGE_SIZE}.")

    status = request.args.get("status")
    if status is not None and status not in {"open", "investigating", "contained", "resolved", "false_positive"}:
        raise ApiError(400, "validation_error", "Unknown incident status.")

    with connection().cursor() as cur:
        cur.execute(LIST_SQL, {"cursor_id": _int_param("cursor"), "status": status, "limit": limit})
        rows = cur.fetchall()

    return jsonify(
        {
            "data": [_serialise(row, row["threat_count"]) for row in rows],
            "next_cursor": str(rows[-1]["id"]) if len(rows) == limit else None,
        }
    )


@bp.post("/<int:incident_id>/respond/")
@require_scope(config.RESPOND)
def respond(incident_id: int):
    """Re-evaluate containment for one incident.

    The caller names the incident and nothing else: the action list, policy,
    risk and results are all determined by the engine from authoritative state.
    Idempotent, so calling it repeatedly does not re-contain anything.
    """
    if request.is_json:
        payload = request.get_json(silent=True)
        if payload is None:
            raise ApiError(400, "malformed_json", "The request body is not valid JSON.")
        if payload:
            raise ApiError(
                400,
                "validation_error",
                "The response engine determines the action, policy, risk and result.",
                [{"field": name, "message": "Not accepted from a client."} for name in sorted(payload)],
            )

    conn = connection()
    outcome = respond_to_incident(conn, incident_id, actor=f"api:{g.api_key.name}")
    if outcome is None:
        raise ApiError(404, "not_found", "No such incident.")

    # Committed before responding so a failed audit write cannot be reported as
    # successful containment.
    conn.commit()
    return jsonify(outcome), 200


@bp.get("/<int:incident_id>")
@require_scope(config.READ)
def get_incident(incident_id: int):
    conn = connection()
    with conn.cursor() as cur:
        cur.execute(f"SELECT {COLUMNS} FROM incidents WHERE id = %s", (incident_id,))
        row = cur.fetchone()
    if row is None:
        raise ApiError(404, "not_found", "No such incident.")

    with conn.cursor() as cur:
        cur.execute(THREATS_SQL, (incident_id,))
        threats = cur.fetchall()

    with conn.cursor() as cur:
        cur.execute(
            f"SELECT {response_columns} FROM responses WHERE incident_id = %s ORDER BY id",
            (incident_id,),
        )
        actions = cur.fetchall()

    # Everything an analyst needs for one incident in a single request. Each
    # query is bounded by incident membership, so the count does not grow with
    # the number of threats -- this is not an N+1.
    with conn.cursor() as cur:
        cur.execute(DECISIONS_FOR_INCIDENT_SQL, (incident_id,))
        decisions = cur.fetchall()
    with conn.cursor() as cur:
        cur.execute(INCIDENT_SUBJECTS_SQL, (incident_id,))
        subjects = cur.fetchall()
    with conn.cursor() as cur:
        cur.execute(INCIDENT_SOURCES_SQL, (incident_id,))
        sources = cur.fetchall()
    with conn.cursor() as cur:
        cur.execute(INCIDENT_DEVICES_SQL, (incident_id,))
        devices = cur.fetchall()

    return jsonify(
        _serialise(row, len(threats))
        | {
            "threats": [_serialise_threat(t) for t in threats],
            "timeline": build_timeline(conn, incident_id),
            "responses": [serialise_response(a) for a in actions],
            "zero_trust": [
                {
                    "id": d["id"],
                    "decided_at": d["decided_at"].isoformat(),
                    "subject": d["subject_username"],
                    "subject_role": d["subject_role"],
                    "device_state": d["device_state"],
                    "resource": d["resource"],
                    "sensitivity": d["sensitivity"],
                    "decision": d["decision"],
                    "policy": d["policy"],
                    "reason": d["reason"],
                    "factors": d["factors"].get("factors", []) if isinstance(d["factors"], dict) else [],
                }
                for d in decisions
            ],
            "containment": {
                "subjects": [
                    {"id": s["id"], "username": s["username"], "role": s["role"], "contained": s["contained"]}
                    for s in subjects
                ],
                "sources": [{"source_ip": s["source_ip"], "blocked": s["blocked"]} for s in sources],
                "devices": [
                    {
                        "id": d["id"],
                        "fingerprint": d["device_fingerprint"],
                        "isolated": d["isolated"],
                        "trust_score": float(d["trust_score"]),
                    }
                    for d in devices
                ],
            },
        }
    )
