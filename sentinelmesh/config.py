import re
import os
from dataclasses import dataclass
from decimal import Decimal

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

# A client may name the device an event came from. The fingerprint is only ever
# used to look up an authoritative devices row belonging to the event's own
# user; the trust score itself is never taken from metadata.
DEVICE_FINGERPRINT_KEY = "device_fingerprint"

# --- risk engine -------------------------------------------------------------
#
# Severity sets a baseline, confidence scales it, and independent context adds
# to it. Confidence is deliberately not additive: severity and confidence both
# describe the same detection, so adding both would count one signal twice.

RISK_MODEL_VERSION = "risk.v1"

RISK_MIN_SCORE = 0
RISK_MAX_SCORE = 100

# Each baseline sits just inside its own band rather than on the floor, so
# ordinary confidence variation keeps a threat in the band its severity implies
# and only substantially weak confidence demotes it. On the floor, any
# confidence below 1.0 would demote every detection by a band.
RISK_SEVERITY_BASELINE = {"info": 10, "low": 22, "medium": 45, "high": 66, "critical": 88}

# weighted = baseline * (FLOOR + (1 - FLOOR) * confidence). A floor of 0.70
# means even a barely-confident detection keeps most of its severity, while a
# fully confident one gets no bonus beyond its baseline.
RISK_CONFIDENCE_FLOOR = Decimal("0.70")

# Compromise of a privileged identity is worth more than of an unprivileged one.
# Read from users.role, never from event metadata.
RISK_ROLE_POINTS = {"admin": 8, "responder": 4, "analyst": 4, "viewer": 0}

RISK_DEVICE_TRUST_THRESHOLD = Decimal("70")
RISK_UNTRUSTED_DEVICE_POINTS = 6
RISK_UNKNOWN_DEVICE_POINTS = 4

RISK_SENSITIVE_RESOURCE_POINTS = 6

# Breadth of attack, not repetition: counts distinct prior threat types from the
# same source address. Repetition is already inside the brute-force evidence.
RISK_ESCALATION_POINTS_PER_TYPE = 3
RISK_ESCALATION_MAX_POINTS = 6
RISK_ESCALATION_WINDOW_SECONDS = 86_400

# (lower bound, upper bound, label); bounds inclusive, covering 0..100.
RISK_LEVEL_BANDS = ((0, 29, "low"), (30, 59, "medium"), (60, 79, "high"), (80, 100, "critical"))

# --- correlation / incident engine -------------------------------------------

CORRELATION_MODEL_VERSION = "correlation.v1"

# Measured from an incident's last_activity_at, so the window slides and a
# sustained campaign extends it. Chosen to sit well above the 120s brute-force
# window -- so a campaign that trips that rule repeatedly stays one incident --
# while staying short enough that two unrelated scans of the same host hours
# apart do not merge into one campaign.
CORRELATION_WINDOW_SECONDS = 1800

# Link signal weights. A link's confidence is their sum, clamped.
CORRELATION_WEIGHT_SAME_SOURCE = Decimal("0.40")
CORRELATION_WEIGHT_SAME_USER = Decimal("0.15")
CORRELATION_WEIGHT_TEMPORAL_MAX = Decimal("0.25")
CORRELATION_WEIGHT_PROGRESSION = Decimal("0.20")
CORRELATION_CONFIDENCE_MIN = Decimal("0.050")
CORRELATION_CONFIDENCE_MAX = Decimal("0.990")
# At or above this, correlation is reported as HIGH and earns a risk bonus.
CORRELATION_STRONG_THRESHOLD = Decimal("0.750")

# Attack stage of each threat type. Ordering is what makes progression
# meaningful; a set of threats spanning stages in chronological order is a
# campaign, whereas three simultaneous detections in one stage is not.
ATTACK_STAGES = {
    THREAT_BRUTE_FORCE: (1, "Credential Abuse"),
    THREAT_PRIVILEGED_ACCESS: (2, "Privileged Access Attempt"),
    THREAT_SQL_INJECTION: (3, "Application Injection"),
}

ATTACK_STAGES_BY_NUMBER = {number: name for number, name in ATTACK_STAGES.values()}

INCIDENT_MULTI_STAGE_MIN_STAGES = 2

CLASSIFICATION_MULTI_STAGE = "multi_stage_attack"
CLASSIFICATION_CREDENTIAL = "credential_attack"
CLASSIFICATION_PRIVILEGE = "privilege_escalation"
CLASSIFICATION_APPLICATION = "application_attack"
CLASSIFICATION_UNCLASSIFIED = "unclassified"

CLASSIFICATION_BY_STAGE = {
    1: CLASSIFICATION_CREDENTIAL,
    2: CLASSIFICATION_PRIVILEGE,
    3: CLASSIFICATION_APPLICATION,
}

# Campaign-level risk. The base is the WORST member threat, never an average,
# so a severe threat cannot be diluted by mild ones. Only signals invisible to
# a single threat's score are added; identity and resource context are already
# inside every member score and are deliberately not re-counted here.
INCIDENT_BREADTH_POINTS_PER_TYPE = 3
INCIDENT_BREADTH_MAX_POINTS = 6
INCIDENT_PROGRESSION_POINTS = 6
INCIDENT_STRONG_CORRELATION_POINTS = 3

# --- zero-trust decision engine ----------------------------------------------
#
# Authentication alone does not imply authorization. The engine consumes the
# risk the risk engine produced and the incidents the correlation engine built;
# it never recomputes either.

ZT_MODEL_VERSION = "zerotrust.v1"

ALLOW = "allow"
STEP_UP = "step_up"
DENY = "deny"

# Band floors, reused from the risk model rather than restated, so tuning a band
# cannot leave the authorization thresholds behind.
RISK_BAND_FLOOR = {label: lower for lower, _upper, label in RISK_LEVEL_BANDS}

ZT_ELEVATED_RISK = RISK_BAND_FLOOR["medium"]
ZT_HIGH_RISK = RISK_BAND_FLOOR["high"]
ZT_CRITICAL_RISK = RISK_BAND_FLOOR["critical"]

# A threat counts as active for this long after detection. Measured on
# detected_at, the server clock, so a client cannot age out its own threats.
ZT_THREAT_WINDOW_SECONDS = 3600
# Incidents are gated on status, not time: an untriaged incident stays relevant
# until an analyst moves it on. Nothing here closes an incident.
ZT_ACTIVE_INCIDENT_STATUSES = ("open", "investigating")
# Caps the context queries so one decision cannot scan an unbounded history.
ZT_CONTEXT_LIMIT = 50

DEVICE_TRUSTED = "trusted"
DEVICE_UNTRUSTED = "untrusted"
DEVICE_UNKNOWN = "unknown"

SENSITIVITY_PUBLIC = "public"
SENSITIVITY_INTERNAL = "internal"
SENSITIVITY_SENSITIVE = "sensitive"
SENSITIVITY_CRITICAL = "critical"
# Ascending order; index in this tuple is the comparison rank.
SENSITIVITY_ORDER = (SENSITIVITY_PUBLIC, SENSITIVITY_INTERNAL, SENSITIVITY_SENSITIVE, SENSITIVITY_CRITICAL)

# Longest matching prefix wins. Derived server-side: letting a caller declare a
# resource's sensitivity would let it relabel /api/admin as public.
RESOURCE_SENSITIVITY_PREFIXES = (
    ("/api/admin", SENSITIVITY_CRITICAL),
    ("/admin", SENSITIVITY_CRITICAL),
    ("/api/internal", SENSITIVITY_CRITICAL),
    ("/api/reports", SENSITIVITY_SENSITIVE),
    ("/api/users", SENSITIVITY_SENSITIVE),
    ("/api/search", SENSITIVITY_INTERNAL),
    ("/api/dashboard", SENSITIVITY_INTERNAL),
    ("/api/public", SENSITIVITY_PUBLIC),
    ("/health", SENSITIVITY_PUBLIC),
)
# An unrecognised resource is treated as sensitive rather than public: where
# uncertainty affects authorization, fail closed.
DEFAULT_RESOURCE_SENSITIVITY = SENSITIVITY_SENSITIVE

# Resources at or above this rank require a privileged role (PRIVILEGED_ROLES).
ZT_PRIVILEGED_SENSITIVITY = SENSITIVITY_CRITICAL

# --- automated response engine -----------------------------------------------
#
# Containment is applied INSIDE SentinelMesh. Nothing here touches a firewall,
# a router, an operating system or any external system: every action changes
# SentinelMesh's own authoritative state, which the zero-trust engine then
# enforces on subsequent access decisions.

RESPONSE_MODEL_VERSION = "response.v1"

ACTION_ALERT = "alert"
ACTION_REQUIRE_STEP_UP = "require_step_up"
ACTION_CONTAIN_SUBJECT = "contain_subject"
ACTION_BLOCK_SOURCE = "block_source"
ACTION_ISOLATE_DEVICE = "isolate_device"

RESPONSE_ACTIONS = (
    ACTION_ALERT,
    ACTION_REQUIRE_STEP_UP,
    ACTION_CONTAIN_SUBJECT,
    ACTION_BLOCK_SOURCE,
    ACTION_ISOLATE_DEVICE,
)

# Reusing the existing response_result enum. 'succeeded' is an action that ran
# now; 'already_applied' one that was already in effect and was not re-run.
RESULT_EXECUTED = "succeeded"
RESULT_ALREADY_APPLIED = "already_applied"
RESULT_FAILED = "failed"

RESPONSE_POLICY_CRITICAL_INCIDENT = "critical_incident_containment"
RESPONSE_POLICY_CRITICAL_THREAT = "critical_threat_containment"
RESPONSE_POLICY_HIGH_INCIDENT = "high_incident_escalation"
RESPONSE_POLICY_HIGH_THREAT = "high_threat_escalation"
RESPONSE_POLICY_MEDIUM = "medium_monitoring"
RESPONSE_POLICY_LOW = "low_no_containment"

# Caps the context queries so responding to one incident cannot walk an
# unbounded history of members.
RESPONSE_CONTEXT_LIMIT = 50

READ = "read"
WRITE = "write"
# Asking for an access decision is neither reading telemetry nor writing it. A
# separate scope keeps an ingest agent's credential from acting as a policy
# enforcement point.
DECIDE = "decide"
# Asking the engine to re-evaluate containment for an incident is a distinct
# privilege again: an ingest agent must not be able to trigger containment.
RESPOND = "respond"
VALID_SCOPES = frozenset({READ, WRITE, DECIDE, RESPOND})


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
