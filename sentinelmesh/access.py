import ipaddress

from flask import Blueprint, g, jsonify, request

from . import config
from .auth import require_scope
from .db import connection
from .errors import ApiError
from .zerotrust import evaluate_access, load_access_context, record_decision

bp = Blueprint("access", __name__, url_prefix="/api/access")

# The caller names the subject, the claimed device, the observed address and the
# resource. Nothing else.
ALLOWED_FIELDS = frozenset({"resource", "subject_user_id", "device_fingerprint", "source_ip"})

# Named separately only to return a clearer error: everything outside
# ALLOWED_FIELDS is rejected regardless.
ENGINE_OWNED_FIELDS = frozenset(
    {
        "role",
        "user_role",
        "authenticated",
        "risk_score",
        "risk_level",
        "severity",
        "trust_score",
        "device_trust",
        "device_state",
        "incident_id",
        "incident_risk",
        "correlation_confidence",
        "classification",
        "decision",
        "policy",
        # Derived from the resource path by server policy. A caller that could
        # declare this would relabel /api/admin as public.
        "sensitivity",
    }
)

DECISIONS_SQL = """
    SELECT id, decided_at, api_key, subject_user_id, subject_username, subject_role,
           authenticated, device_fingerprint, device_state, device_trust, source_ip,
           resource, sensitivity, decision, policy, reason, factors,
           max_threat_risk, incident_id, incident_risk
    FROM access_decisions
    WHERE (%(cursor_id)s::bigint IS NULL OR id < %(cursor_id)s::bigint)
      AND (%(subject_user_id)s::bigint IS NULL OR subject_user_id = %(subject_user_id)s::bigint)
    ORDER BY id DESC
    LIMIT %(limit)s
"""


def _validate(payload) -> dict:
    if not isinstance(payload, dict):
        raise ApiError(400, "validation_error", "The request body must be a JSON object.")

    details = []
    for name in sorted(set(payload) - ALLOWED_FIELDS):
        if name in ENGINE_OWNED_FIELDS:
            details.append(
                {
                    "field": name,
                    "message": "This value is derived by the zero-trust engine and cannot be supplied by a client.",
                }
            )
        else:
            details.append({"field": name, "message": "Unknown field."})

    resource = payload.get("resource")
    if resource is None:
        details.append({"field": "resource", "message": "This field is required."})
    elif not isinstance(resource, str) or not resource.strip():
        details.append({"field": "resource", "message": "Must be a non-empty string."})
    elif len(resource) > 512:
        details.append({"field": "resource", "message": "Must be 512 characters or fewer."})

    subject = payload.get("subject_user_id")
    if subject is not None and (isinstance(subject, bool) or not isinstance(subject, int) or subject < 1):
        details.append({"field": "subject_user_id", "message": "Must be a positive integer identifier."})

    fingerprint = payload.get("device_fingerprint")
    if fingerprint is not None and (not isinstance(fingerprint, str) or len(fingerprint) > 256):
        details.append({"field": "device_fingerprint", "message": "Must be a string of 256 characters or fewer."})

    source_ip = payload.get("source_ip")
    if source_ip is not None:
        if not isinstance(source_ip, str):
            details.append({"field": "source_ip", "message": "Must be a string."})
        else:
            try:
                source_ip = str(ipaddress.ip_address(source_ip.strip()))
            except ValueError:
                details.append({"field": "source_ip", "message": "Must be a valid IPv4 or IPv6 address."})

    if details:
        raise ApiError(400, "validation_error", "The access request failed validation.", details)

    return {
        "resource": resource.strip(),
        "subject_user_id": subject,
        "device_fingerprint": fingerprint,
        "source_ip": source_ip,
    }


def _serialise_record(row: dict) -> dict:
    return {
        "id": row["id"],
        "decided_at": row["decided_at"].isoformat(),
        "api_key": row["api_key"],
        "subject": {
            "user_id": row["subject_user_id"],
            "username": row["subject_username"],
            "role": row["subject_role"],
            "authenticated": row["authenticated"],
        },
        "device": {
            "fingerprint": row["device_fingerprint"],
            "state": row["device_state"],
            "trust": float(row["device_trust"]) if row["device_trust"] is not None else None,
        },
        "source_ip": str(row["source_ip"]) if row["source_ip"] is not None else None,
        "resource": row["resource"],
        "sensitivity": row["sensitivity"],
        "decision": row["decision"],
        "policy": row["policy"],
        "reason": row["reason"],
        "factors": row["factors"],
        "max_threat_risk": row["max_threat_risk"],
        "incident_id": row["incident_id"],
        "incident_risk": row["incident_risk"],
    }


@bp.post("/decision/")
@require_scope(config.DECIDE)
def decide():
    if not request.is_json:
        raise ApiError(415, "unsupported_media_type", "Content-Type must be application/json.")
    payload = request.get_json(silent=True)
    if payload is None:
        raise ApiError(400, "malformed_json", "The request body is not valid JSON.")

    asked = _validate(payload)
    conn = connection()
    context = load_access_context(conn, **asked)
    decision = evaluate_access(context)
    record = record_decision(conn, context, decision, g.api_key.name)

    # Committed before the verdict is returned. If the audit record cannot be
    # written the request fails rather than handing back an unaudited ALLOW.
    conn.commit()

    return (
        jsonify(
            {
                "decision_id": record["id"],
                "decided_at": record["decided_at"].isoformat(),
                "decision": decision.decision,
                "policy": decision.policy,
                "reason": decision.reason,
                "factors": decision.factors,
                "context": {
                    "subject": {
                        "user_id": context.subject_user_id,
                        "username": context.subject_username,
                        "role": context.subject_role,
                        "authenticated": context.authenticated,
                    },
                    "device": {"state": context.device_state},
                    "threat": {
                        "max_risk": context.max_threat_risk,
                        "active_count": context.threat_count,
                        "top": context.top_threat,
                    },
                    "incident": context.incident,
                    "resource": {"path": context.resource, "sensitivity": context.sensitivity},
                },
            }
        ),
        200,
    )


@bp.get("/decisions/")
@require_scope(config.READ)
def list_decisions():
    raw_limit = request.args.get("limit")
    try:
        limit = int(raw_limit) if raw_limit is not None else config.DEFAULT_PAGE_SIZE
    except ValueError:
        raise ApiError(400, "validation_error", "limit must be an integer.") from None
    if not 1 <= limit <= config.MAX_PAGE_SIZE:
        raise ApiError(400, "validation_error", f"limit must be between 1 and {config.MAX_PAGE_SIZE}.")

    def optional_int(name):
        raw = request.args.get(name)
        if raw is None:
            return None
        try:
            return int(raw)
        except ValueError:
            raise ApiError(400, "validation_error", f"{name} must be an integer.") from None

    with connection().cursor() as cur:
        cur.execute(
            DECISIONS_SQL,
            {
                "cursor_id": optional_int("cursor"),
                "subject_user_id": optional_int("subject_user_id"),
                "limit": limit,
            },
        )
        rows = cur.fetchall()

    return jsonify(
        {
            "data": [_serialise_record(row) for row in rows],
            "next_cursor": str(rows[-1]["id"]) if len(rows) == limit else None,
        }
    )
