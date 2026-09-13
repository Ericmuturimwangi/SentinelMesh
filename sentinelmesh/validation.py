import ipaddress
import json
import math
from datetime import datetime, timedelta, timezone

from . import config
from .errors import ApiError

ALLOWED_FIELDS = frozenset({"event_type", "user_id", "source_ip", "occurred_at", "metadata"})

# Fields a client must never be able to assert. They are rejected by the
# allowlist above; naming them separately only buys a clearer error message.
SERVER_OWNED_FIELDS = frozenset(
    {"id", "received_at", "severity", "risk_score", "confidence", "threat_type", "status", "result", "incident_id"}
)


class Detail(list):
    """Accumulates field-level problems so one response reports them all."""

    def add(self, field: str, message: str) -> None:
        self.append({"field": field, "message": message})


def _reject_unknown_fields(payload: dict, details: Detail) -> None:
    for field in sorted(set(payload) - ALLOWED_FIELDS):
        if field in SERVER_OWNED_FIELDS:
            details.add(field, "This field is assigned by SentinelMesh and cannot be supplied by a client.")
        else:
            details.add(field, "Unknown field.")


def _validate_event_type(value, details: Detail):
    if value is None:
        details.add("event_type", "This field is required.")
        return None
    if not isinstance(value, str):
        details.add("event_type", "Must be a string.")
        return None
    if value not in config.ALLOWED_EVENT_TYPES:
        details.add("event_type", "Not a recognised event type.")
        return None
    return value


def _validate_user_id(value, details: Detail):
    if value is None:
        return None
    # bool is an int subclass in Python, and `true` would silently become 1.
    if isinstance(value, bool) or not isinstance(value, int):
        details.add("user_id", "Must be an integer identifier.")
        return None
    if value < 1:
        details.add("user_id", "Must be a positive integer.")
        return None
    return value


def _validate_source_ip(value, details: Detail):
    if value is None:
        return None
    if not isinstance(value, str):
        details.add("source_ip", "Must be a string.")
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        details.add("source_ip", "Must be a valid IPv4 or IPv6 address.")
        return None


def _validate_occurred_at(value, details: Detail, now: datetime):
    if value is None:
        return now
    if not isinstance(value, str):
        details.add("occurred_at", "Must be an ISO 8601 timestamp string.")
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        details.add("occurred_at", "Must be a valid ISO 8601 timestamp.")
        return None
    if parsed.tzinfo is None:
        details.add("occurred_at", "Must include a UTC offset.")
        return None
    if parsed > now + timedelta(seconds=config.MAX_CLOCK_SKEW_SECONDS):
        details.add("occurred_at", "Timestamp is too far in the future.")
        return None
    if parsed.year < config.MIN_EVENT_YEAR:
        details.add("occurred_at", "Timestamp is implausibly old.")
        return None
    return parsed


def _walk_metadata(node, depth: int, state: dict, details: Detail) -> None:
    if depth > config.MAX_METADATA_DEPTH:
        details.add("metadata", f"Nested more than {config.MAX_METADATA_DEPTH} levels deep.")
        state["failed"] = True
        return

    if isinstance(node, dict):
        for key, value in node.items():
            if not isinstance(key, str):
                details.add("metadata", "Object keys must be strings.")
                state["failed"] = True
                return
            if "\x00" in key:
                details.add("metadata", "Keys must not contain null bytes.")
                state["failed"] = True
                return
            if len(key) > 128:
                details.add("metadata", "Object keys must be 128 characters or fewer.")
                state["failed"] = True
                return
            state["keys"] += 1
            if state["keys"] > config.MAX_METADATA_KEYS:
                details.add("metadata", f"Contains more than {config.MAX_METADATA_KEYS} keys.")
                state["failed"] = True
                return
            _walk_metadata(value, depth + 1, state, details)
            if state["failed"]:
                return
    elif isinstance(node, list):
        if len(node) > config.MAX_METADATA_ARRAY:
            details.add("metadata", f"Arrays must hold {config.MAX_METADATA_ARRAY} items or fewer.")
            state["failed"] = True
            return
        for item in node:
            _walk_metadata(item, depth + 1, state, details)
            if state["failed"]:
                return
    elif isinstance(node, str):
        # jsonb cannot store a NUL, and json.loads accepts the escape happily.
        if "\x00" in node:
            details.add("metadata", "String values must not contain null bytes.")
            state["failed"] = True
        elif len(node) > config.MAX_METADATA_STRING:
            details.add("metadata", f"String values must be {config.MAX_METADATA_STRING} characters or fewer.")
            state["failed"] = True
    elif isinstance(node, float):
        # json.loads produces NaN/Infinity by default; jsonb rejects both.
        if not math.isfinite(node):
            details.add("metadata", "Numbers must be finite.")
            state["failed"] = True
    elif not isinstance(node, (int, bool)) and node is not None:
        details.add("metadata", "Unsupported value type.")
        state["failed"] = True


def _validate_metadata(value, details: Detail):
    if value is None:
        return {}
    if not isinstance(value, dict):
        details.add("metadata", "Must be a JSON object.")
        return None

    # The walk runs first: it rejects the non-finite floats that would otherwise
    # make json.dumps(allow_nan=False) raise. The body is already capped by
    # MAX_CONTENT_LENGTH, so walking before measuring is bounded work.
    state = {"keys": 0, "failed": False}
    _walk_metadata(value, 1, state, details)
    if state["failed"]:
        return None

    encoded = json.dumps(value, separators=(",", ":"), allow_nan=False, ensure_ascii=False)
    if len(encoded.encode("utf-8")) > config.MAX_METADATA_BYTES:
        details.add("metadata", f"Exceeds the {config.MAX_METADATA_BYTES} byte limit.")
        return None

    return value


def validate_event(payload, now: datetime | None = None) -> dict:
    """Validate and normalise an ingest payload, or raise ApiError(400)."""
    now = now or datetime.now(timezone.utc)

    if not isinstance(payload, dict):
        raise ApiError(400, "validation_error", "The request body must be a JSON object.")

    details = Detail()
    _reject_unknown_fields(payload, details)

    normalised = {
        "event_type": _validate_event_type(payload.get("event_type"), details),
        "user_id": _validate_user_id(payload.get("user_id"), details),
        "source_ip": _validate_source_ip(payload.get("source_ip"), details),
        "occurred_at": _validate_occurred_at(payload.get("occurred_at"), details, now),
        "metadata": _validate_metadata(payload.get("metadata"), details),
    }

    if details:
        raise ApiError(400, "validation_error", "The event failed validation.", list(details))

    return normalised
