from flask import Blueprint, jsonify, request

from . import config
from .auth import require_scope
from .db import connection
from .errors import ApiError

bp = Blueprint("threats", __name__, url_prefix="/api/threats")

COLUMNS = "id, event_id, threat_type, severity, confidence, rule_id, evidence, detected_at, incident_id"

# Keyset paging on the primary key: threat ids are monotonic, so this needs no
# index beyond threats_pkey.
LIST_SQL = f"""
    SELECT {COLUMNS}
    FROM threats
    WHERE (%(cursor_id)s::bigint IS NULL OR id < %(cursor_id)s::bigint)
      AND (%(event_id)s::bigint IS NULL OR event_id = %(event_id)s::bigint)
    ORDER BY id DESC
    LIMIT %(limit)s
"""


def _serialise(row: dict) -> dict:
    return {
        "id": row["id"],
        "event_id": row["event_id"],
        "threat_type": row["threat_type"],
        "severity": row["severity"],
        "confidence": float(row["confidence"]),
        "rule_id": row["rule_id"],
        "evidence": row["evidence"],
        "detected_at": row["detected_at"].isoformat(),
        "incident_id": row["incident_id"],
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
def list_threats():
    limit = _int_param("limit", config.DEFAULT_PAGE_SIZE)
    if not 1 <= limit <= config.MAX_PAGE_SIZE:
        raise ApiError(400, "validation_error", f"limit must be between 1 and {config.MAX_PAGE_SIZE}.")

    with connection().cursor() as cur:
        cur.execute(
            LIST_SQL,
            {"cursor_id": _int_param("cursor"), "event_id": _int_param("event_id"), "limit": limit},
        )
        rows = cur.fetchall()

    return jsonify(
        {
            "data": [_serialise(row) for row in rows],
            "next_cursor": str(rows[-1]["id"]) if len(rows) == limit else None,
        }
    )


@bp.get("/<int:threat_id>")
@require_scope(config.READ)
def get_threat(threat_id: int):
    with connection().cursor() as cur:
        cur.execute(f"SELECT {COLUMNS} FROM threats WHERE id = %s", (threat_id,))
        row = cur.fetchone()

    if row is None:
        raise ApiError(404, "not_found", "No such threat.")
    return jsonify(_serialise(row))
