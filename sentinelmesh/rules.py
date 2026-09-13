"""Detection rules.

Every rule is a pure decision over one stored event plus whatever it reads back
from the database through parameterised queries. Rules never build SQL from
event data, never evaluate a payload, and never copy a value held under a
sensitive-looking key into stored evidence.

A rule returns a Detection or None. Nothing else.
"""

import re
from dataclasses import dataclass, field

from . import config


@dataclass(frozen=True)
class Detection:
    rule_id: str
    threat_type: str
    severity: str
    confidence: float
    reason: str
    evidence: dict = field(default_factory=dict)

    def summary(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "reason": self.reason,
        }


# --- rule 1: brute force -----------------------------------------------------

RECENT_FAILURES_SQL = """
    SELECT id
    FROM events
    WHERE event_type = %(event_type)s
      AND source_ip = %(source_ip)s::inet
      AND occurred_at <= %(occurred_at)s
      AND occurred_at > %(occurred_at)s - make_interval(secs => %(window)s)
    ORDER BY occurred_at DESC, id DESC
    LIMIT %(limit)s
"""


def brute_force(conn, event) -> Detection | None:
    """Repeated failed logins from one source address inside a time window."""
    if event["event_type"] != config.BRUTE_FORCE_EVENT_TYPE or event["source_ip"] is None:
        return None

    with conn.cursor() as cur:
        cur.execute(
            RECENT_FAILURES_SQL,
            {
                "event_type": config.BRUTE_FORCE_EVENT_TYPE,
                "source_ip": str(event["source_ip"]),
                "occurred_at": event["occurred_at"],
                "window": config.BRUTE_FORCE_WINDOW_SECONDS,
                "limit": config.BRUTE_FORCE_THRESHOLD,
            },
        )
        failures = [row["id"] for row in cur.fetchall()]

    if len(failures) < config.BRUTE_FORCE_THRESHOLD:
        return None

    source_ip = str(event["source_ip"])
    return Detection(
        rule_id="brute_force.v1",
        threat_type=config.THREAT_BRUTE_FORCE,
        severity=config.BRUTE_FORCE_SEVERITY,
        confidence=config.BRUTE_FORCE_CONFIDENCE,
        reason=(
            f"{len(failures)} failed login attempts from {source_ip} "
            f"within {config.BRUTE_FORCE_WINDOW_SECONDS} seconds"
        ),
        evidence={
            "source_ip": source_ip,
            "failure_count": len(failures),
            "threshold": config.BRUTE_FORCE_THRESHOLD,
            "window_seconds": config.BRUTE_FORCE_WINDOW_SECONDS,
            "contributing_event_ids": sorted(failures),
        },
    )


# --- rule 2: SQL injection ---------------------------------------------------

# Deliberately small. Each pattern names a specific, well-understood injection
# shape; the goal is defensible evidence, not exhaustive coverage. None of these
# nest quantifiers, so they cannot backtrack catastrophically.
SQLI_PATTERNS = (
    # The trailing quote is optional: a real payload such as `admin' OR 'a'='a`
    # is deliberately left unterminated so the injected quote closes it.
    ("tautology", re.compile(r"(?i)\b(?:or|and)\b\s+(['\"]?)(\w+)\1\s*=\s*(['\"]?)\2\3?")),
    ("union_select", re.compile(r"(?i)\bunion\b\s+(?:all\s+)?\bselect\b")),
    ("stacked_query", re.compile(r"(?i);\s*(?:drop|delete|insert|update|truncate|alter)\b")),
    ("comment_terminator", re.compile(r"'\s*(?:--|#)|/\*.*?\*/")),
    ("time_based", re.compile(r"(?i)\b(?:sleep|pg_sleep|benchmark|waitfor\s+delay|xp_cmdshell|load_file)\s*\(")),
)


def _walk_strings(node, path: str, depth: int = 0):
    """Yield (json path, string) pairs, skipping sensitive keys entirely."""
    if depth > config.MAX_METADATA_DEPTH:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and config.SENSITIVE_KEY_PATTERN.search(key):
                continue
            yield from _walk_strings(value, f"{path}.{key}" if path else str(key), depth + 1)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from _walk_strings(item, f"{path}[{index}]", depth + 1)
    elif isinstance(node, str):
        yield path, node


def sql_injection(conn, event) -> Detection | None:
    """SQL injection indicators in the request descriptor.

    The payload is only ever matched against a regex. It is never executed,
    interpolated into a query, or echoed back in full.
    """
    if event["event_type"] not in config.SQLI_EVENT_TYPES:
        return None

    indicators = []
    for path, value in _walk_strings(event["metadata"], ""):
        for name, pattern in SQLI_PATTERNS:
            match = pattern.search(value)
            if match:
                indicators.append(
                    {
                        "pattern": name,
                        "field": path,
                        "snippet": match.group(0)[: config.SQLI_SNIPPET_CHARS],
                    }
                )

    if not indicators:
        return None

    distinct = {item["pattern"] for item in indicators}
    confidence = min(
        config.SQLI_CONFIDENCE_BASE + config.SQLI_CONFIDENCE_STEP * (len(distinct) - 1),
        config.SQLI_CONFIDENCE_MAX,
    )
    fields = sorted({item["field"] for item in indicators})

    return Detection(
        rule_id="sql_injection.v1",
        threat_type=config.THREAT_SQL_INJECTION,
        severity=config.SQLI_SEVERITY,
        confidence=round(confidence, 3),
        reason=(
            f"SQL injection indicators ({', '.join(sorted(distinct))}) "
            f"in request field(s): {', '.join(fields)}"
        ),
        evidence={"indicators": indicators, "matched_patterns": sorted(distinct), "fields": fields},
    )


# --- rule 3: unauthorized privileged access ----------------------------------

ACTOR_ROLE_SQL = "SELECT role FROM users WHERE id = %s"


def privileged_access(conn, event) -> Detection | None:
    """A principal without the admin role reaching a privileged resource.

    The path comes from client-supplied metadata, but the role is read from the
    users table. Trusting a role asserted in metadata would let an attacker
    suppress this detection by claiming to be an admin.
    """
    if event["event_type"] not in config.PRIVILEGED_EVENT_TYPES:
        return None

    metadata = event["metadata"] if isinstance(event["metadata"], dict) else {}
    path = metadata.get("path")
    if not isinstance(path, str):
        return None

    matched_prefix = next((p for p in config.PRIVILEGED_PATH_PREFIXES if path.startswith(p)), None)
    if matched_prefix is None:
        return None

    role = None
    if event["user_id"] is not None:
        with conn.cursor() as cur:
            cur.execute(ACTOR_ROLE_SQL, (event["user_id"],))
            row = cur.fetchone()
            role = row["role"] if row else None

    if role in config.PRIVILEGED_ROLES:
        return None

    actor = f"user {event['user_id']} with role {role!r}" if role else "an unauthenticated client"
    method = metadata.get("method")
    return Detection(
        rule_id="privileged_access.v1",
        threat_type=config.THREAT_PRIVILEGED_ACCESS,
        severity=config.PRIVILEGED_SEVERITY,
        confidence=config.PRIVILEGED_CONFIDENCE,
        reason=f"{actor} accessed privileged resource {path[:200]}",
        evidence={
            "path": path[:200],
            "method": method if isinstance(method, str) else None,
            "matched_prefix": matched_prefix,
            "actor_user_id": event["user_id"],
            "actor_role": role,
            "required_roles": sorted(config.PRIVILEGED_ROLES),
        },
    )


RULES = (brute_force, sql_injection, privileged_access)
