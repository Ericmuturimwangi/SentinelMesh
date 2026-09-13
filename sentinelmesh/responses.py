from flask import Blueprint, jsonify, request

from . import config
from .auth import require_scope
from .db import connection
from .errors import ApiError

bp = Blueprint("responses", __name__, url_prefix="/api/responses")

COLUMNS = (
    "id, incident_id, threat_id, action, result, policy, reason, evidence, actor, occurred_at"
)

LIST_SQL = f"""
    SELECT {COLUMNS}
    FROM responses
    WHERE (%(cursor_id)s::bigint IS NULL OR id < %(cursor_id)s::bigint)
      AND (%(incident_id)s::bigint IS NULL OR incident_id = %(incident_id)s::bigint)
    ORDER BY id DESC
    LIMIT %(limit)s
"""


def serialise(row: dict) -> dict:
    return {
        "id": row["id"],
        "incident_id": row["incident_id"],
        "threat_id": row["threat_id"],
        "action": row["action"],
        "result": row["result"],
        "policy": row["policy"],
        "reason": row["reason"],
        "evidence": row["evidence"],
        "actor": row["actor"],
        "occurred_at": row["occurred_at"].isoformat(),
    }


def _optional_int(name):
    raw = request.args.get(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        raise ApiError(400, "validation_error", f"{name} must be an integer.") from None


@bp.get("/")
@require_scope(config.READ)
def list_responses():
    limit = _optional_int("limit") or config.DEFAULT_PAGE_SIZE
    if not 1 <= limit <= config.MAX_PAGE_SIZE:
        raise ApiError(400, "validation_error", f"limit must be between 1 and {config.MAX_PAGE_SIZE}.")

    with connection().cursor() as cur:
        cur.execute(
            LIST_SQL,
            {
                "cursor_id": _optional_int("cursor"),
                "incident_id": _optional_int("incident_id"),
                "limit": limit,
            },
        )
        rows = cur.fetchall()

    return jsonify(
        {
            "data": [serialise(row) for row in rows],
            "next_cursor": str(rows[-1]["id"]) if len(rows) == limit else None,
        }
    )
