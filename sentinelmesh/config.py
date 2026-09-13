import os
from dataclasses import dataclass

# The whole request body, enforced by Flask before the JSON parser runs.
MAX_BODY_BYTES = 64 * 1024

# Limits on the client-controlled metadata object. These exist to stop an
# ingest agent from using the jsonb column as free-form storage.
MAX_METADATA_BYTES = 8 * 1024
MAX_METADATA_KEYS = 64
MAX_METADATA_DEPTH = 6
MAX_METADATA_STRING = 1024
MAX_METADATA_ARRAY = 64

# Clock-skew tolerance on a client-asserted occurred_at, and a floor that
# rejects obvious garbage. received_at records the real arrival time either way.
MAX_CLOCK_SKEW_SECONDS = 300
MIN_EVENT_YEAR = 2000

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

# Accepted at the API boundary only. The events.event_type column stays open
# text on purpose so detection rules can introduce new types without a
# migration; this list is what an ingest client is currently allowed to send.
ALLOWED_EVENT_TYPES = frozenset(
    {
        "auth.login.success",
        "auth.login.failure",
        "auth.logout",
        "auth.mfa.challenge",
        "auth.password.change",
        "privilege.escalate",
        "config.change",
        "file.read",
        "file.write",
        "file.delete",
        "process.exec",
        "network.connection",
        "data.egress",
    }
)

READ = "read"
WRITE = "write"
VALID_SCOPES = frozenset({READ, WRITE})


@dataclass(frozen=True)
class ApiKey:
    name: str
    secret: str
    scopes: frozenset[str]


def parse_api_keys(raw: str) -> tuple[ApiKey, ...]:
    """Parse SENTINELMESH_API_KEYS: 'name:scope+scope:secret,name:scope:secret'."""
    keys = []
    for entry in (e.strip() for e in raw.split(",")):
        if not entry:
            continue
        parts = entry.split(":")
        if len(parts) != 3:
            raise ValueError(f"malformed API key entry: expected name:scopes:secret, got {len(parts)} fields")
        name, scopes_raw, secret = (p.strip() for p in parts)
        scopes = frozenset(s for s in scopes_raw.split("+") if s)
        if not name or not secret:
            raise ValueError("API key entries require a non-empty name and secret")
        unknown = scopes - VALID_SCOPES
        if unknown:
            raise ValueError(f"unknown scope(s) for key {name!r}: {sorted(unknown)}")
        if len(secret) < 16:
            raise ValueError(f"API key secret for {name!r} is shorter than 16 characters")
        keys.append(ApiKey(name=name, secret=secret, scopes=scopes))
    return tuple(keys)


def load_config() -> dict:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is not set")

    raw_keys = os.environ.get("SENTINELMESH_API_KEYS", "")
    api_keys = parse_api_keys(raw_keys)
    if not api_keys:
        raise RuntimeError("SENTINELMESH_API_KEYS is empty; refusing to start an unauthenticated ingest API")

    return {
        "DATABASE_URL": database_url,
        "API_KEYS": api_keys,
        "MAX_CONTENT_LENGTH": MAX_BODY_BYTES,
    }
