import base64
import binascii
import logging
from datetime import datetime

import psycopg
from flask import Blueprint, g, jsonify, request, url_for
from psycopg.types.json import Jsonb

from . import config
from .auth import require_scope
from .db import connection
from .detection import run_detection
from .errors import ApiError
from .validation import validate_event

bp = Blueprint("events", __name__, url_prefix="/api/events")
audit = logging.getLogger("sentinelmesh.audit")

COLUMNS = "id, event_type, user_id, source_ip, occurred_at, received_at, metadata"

INSERT_SQL = f"""
    INSERT INTO events (event_type, user_id, source_ip, occurred_at, metadata)
    VALUES (%(event_type)s, %(user_id)s, %(source_ip)s::inet, %(occurred_at)s, %(metadata)s)
    RETURNING {COLUMNS}
"""

# Row-wise comparison against the (occurred_at DESC, id DESC) index, so paging
# stays O(limit) no matter how deep the caller walks.
LIST_SQL = f"""
    SELECT {COLUMNS}
    FROM events
    WHERE %(cursor_ts)s::timestamptz IS NULL
       OR (occurred_at, id) < (%(cursor_ts)s::timestamptz, %(cursor_id)s::bigint)
    ORDER BY occurred_at DESC, id DESC
    LIMIT %(limit)s
"""


def _serialise(row: dict) -> dict:
    return {
        "id": row["id"],
        "event_type": row["event_type"],
        "user_id": row["user_id"],
        "source_ip": str(row["source_ip"]) if row["source_ip"] is not None else None,
        "occurred_at": row["occurred_at"].isoformat(),
        "received_at": row["received_at"].isoformat(),
        "metadata": row["metadata"],
    }


def _encode_cursor(row: dict) -> str:
    raw = f"{row['occurred_at'].isoformat()}|{row['id']}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(value: str) -> tuple[datetime, int]:
    padded = value + "=" * (-len(value) % 4)
    try:
        timestamp, _, event_id = base64.urlsafe_b64decode(padded).decode().rpartition("|")
        return datetime.fromisoformat(timestamp), int(event_id)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise ApiError(400, "validation_error", "Malformed pagination cursor.") from None


def _page_size() -> int:
    raw = request.args.get("limit")
    if raw is None:
        return config.DEFAULT_PAGE_SIZE
    try:
        limit = int(raw)
    except ValueError:
        raise ApiError(400, "validation_error", "limit must be an integer.") from None
    if not 1 <= limit <= config.MAX_PAGE_SIZE:
        raise ApiError(400, "validation_error", f"limit must be between 1 and {config.MAX_PAGE_SIZE}.")
    return limit


@bp.post("/")
@require_scope(config.WRITE)
def create_event():
    if not request.is_json:
        raise ApiError(415, "unsupported_media_type", "Content-Type must be application/json.")

    # silent=True so a parser error surfaces as our own 400 rather than Flask's.
    payload = request.get_json(silent=True)
    if payload is None:
        raise ApiError(400, "malformed_json", "The request body is not valid JSON.")

    event = validate_event(payload)
    event["metadata"] = Jsonb(event["metadata"])

    conn = connection()
    try:
        with conn.cursor() as cur:
            cur.execute(INSERT_SQL, event)
            row = cur.fetchone()
    except psycopg.errors.ForeignKeyViolation:
        conn.rollback()
        raise ApiError(422, "unknown_reference", "The referenced user does not exist.") from None
    except psycopg.errors.IntegrityError:
        conn.rollback()
        raise ApiError(409, "constraint_violation", "The event violates a storage constraint.") from None

    detections = run_detection(conn, row)

    audit.info(
        "event ingested",
        extra={
            "event_id": row["id"],
            "event_type": row["event_type"],
            "api_key": g.api_key.name,
            "remote_addr": request.remote_addr,
        },
    )

    # Summaries only. The full evidence, including payload snippets, is
    # readable through /api/threats/ under the read scope rather than being
    # handed back to whatever agent submitted the event.
    body = _serialise(row) | {"detections": [d.summary() for d in detections]}
    response = jsonify(body)
    response.status_code = 201
    response.headers["Location"] = url_for("events.get_event", event_id=row["id"])
    return response


@bp.get("/")
@require_scope(config.READ)
def list_events():
    limit = _page_size()
    cursor_value = request.args.get("cursor")
    cursor_ts, cursor_id = _decode_cursor(cursor_value) if cursor_value else (None, None)

    with connection().cursor() as cur:
        cur.execute(LIST_SQL, {"cursor_ts": cursor_ts, "cursor_id": cursor_id, "limit": limit})
        rows = cur.fetchall()

    return jsonify(
        {
            "data": [_serialise(row) for row in rows],
            "next_cursor": _encode_cursor(rows[-1]) if len(rows) == limit else None,
        }
    )


@bp.get("/<int:event_id>")
@require_scope(config.READ)
def get_event(event_id: int):
    with connection().cursor() as cur:
        cur.execute(f"SELECT {COLUMNS} FROM events WHERE id = %s", (event_id,))
        row = cur.fetchone()

    if row is None:
        raise ApiError(404, "not_found", "No such event.")
    return jsonify(_serialise(row))
