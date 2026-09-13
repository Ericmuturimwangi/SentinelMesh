import re
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
        # An application or API request. Its metadata carries the request
        # descriptor the resource-access and injection rules inspect:
        #   {"method": "GET", "path": "/api/admin/users", "query": {...}}
        "api.request",
    }
)

# --- detection engine --------------------------------------------------------
#
# Thresholds live here rather than inside the rules so they can be tuned in one
# place and asserted against in tests.

THREAT_BRUTE_FORCE = "credential.bruteforce"
THREAT_SQL_INJECTION = "injection.sql"
THREAT_PRIVILEGED_ACCESS = "access.unauthorized.privileged"

BRUTE_FORCE_EVENT_TYPE = "auth.login.failure"
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 120
BRUTE_FORCE_SEVERITY = "high"
BRUTE_FORCE_CONFIDENCE = 0.900

# Credentials are a classic injection vector, so login attempts are inspected
# alongside ordinary API requests.
SQLI_EVENT_TYPES = frozenset({"api.request", "auth.login.failure", "auth.login.success"})
SQLI_SEVERITY = "critical"
# One indicator is suspicious; independent indicators compound.
SQLI_CONFIDENCE_BASE = 0.750
SQLI_CONFIDENCE_STEP = 0.100
SQLI_CONFIDENCE_MAX = 0.950
SQLI_SNIPPET_CHARS = 120

PRIVILEGED_EVENT_TYPES = frozenset({"api.request"})
PRIVILEGED_PATH_PREFIXES = ("/api/admin", "/admin", "/api/internal")
PRIVILEGED_ROLES = frozenset({"admin"})
PRIVILEGED_SEVERITY = "high"
PRIVILEGED_CONFIDENCE = 0.850

# Metadata under a key like this is never copied into stored evidence.
SENSITIVE_KEY_PATTERN = re.compile(r"(?i)(pass|secret|token|auth|cookie|session|credential|api[_-]?key)")

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
