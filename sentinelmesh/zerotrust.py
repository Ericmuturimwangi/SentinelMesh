"""Zero-trust decision engine.

Answers one question: *should this request be allowed under the current security
context?* It does not detect, does not score a threat, and does not correlate --
it consumes what those engines already produced.

`evaluate_access` is pure: it takes an authoritative context and returns a
verdict, with no database access and no writes. Loading the context and
persisting the verdict are separate, so the policy itself is trivially testable.

There is deliberately no decision confidence. Authorization is a policy
outcome, not a probability; certainty is expressed through the factors that
produced it. Threat confidence (Phase 3) and correlation confidence (Phase 4)
remain distinct concepts and are never mixed into this verdict.
"""

import logging
from dataclasses import dataclass, field
from decimal import Decimal

from psycopg.types.json import Jsonb

from . import config

log = logging.getLogger("sentinelmesh.zerotrust")


@dataclass(frozen=True)
class AccessContext:
    """Authoritative security context. Every field is server-derived.

    The caller names the subject and the resource; it cannot assert the role,
    the device trust, the risk, the incident state, or the sensitivity.
    """

    resource: str
    sensitivity: str
    authenticated: bool = False
    subject_user_id: int | None = None
    subject_username: str | None = None
    subject_role: str | None = None
    subject_exists: bool = False
    device_fingerprint: str | None = None
    device_state: str = config.DEVICE_UNKNOWN
    device_trust: Decimal | None = None
    source_ip: str | None = None
    max_threat_risk: int = 0
    top_threat: dict | None = None
    threat_count: int = 0
    incident: dict | None = None
    incident_risk: int = 0
    # Containment applied by the response engine (Phase 6). These are what make
    # automated containment real: the engine writes the state, this engine
    # enforces it on every subsequent request.
    subject_contained: bool = False
    source_contained: bool = False
    device_isolated: bool = False


@dataclass(frozen=True)
class AccessDecision:
    decision: str
    policy: str
    reason: str
    factors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "model_version": config.ZT_MODEL_VERSION,
            "decision": self.decision,
            "policy": self.policy,
            "reason": self.reason,
            "factors": self.factors,
        }


def sensitivity_for(resource: str) -> str:
    """Classify a resource server-side. Longest matching prefix wins."""
    best, best_length = config.DEFAULT_RESOURCE_SENSITIVITY, -1
    for prefix, sensitivity in config.RESOURCE_SENSITIVITY_PREFIXES:
        if resource.startswith(prefix) and len(prefix) > best_length:
            best, best_length = sensitivity, len(prefix)
    return best


def _rank(sensitivity: str) -> int:
    return config.SENSITIVITY_ORDER.index(sensitivity)


def _at_least_sensitive(context: AccessContext) -> bool:
    return _rank(context.sensitivity) >= _rank(config.SENSITIVITY_SENSITIVE)


# --- policy rules ------------------------------------------------------------
#
# Evaluated strictly in order; the first rule that matches decides. Every DENY
# rule precedes every STEP_UP rule, so a condition that forbids access can never
# be softened by a later rule that would merely challenge it.


def _identity_unauthenticated(c):
    if not c.authenticated:
        return config.DENY, "identity_unauthenticated", "No authenticated principal for this request."
    return None


def _identity_unknown(c):
    if not c.subject_exists:
        return (
            config.DENY,
            "identity_unknown",
            "The named principal does not exist in the identity store.",
        )
    return None


def _critical_incident(c):
    if c.incident is not None and c.incident_risk >= config.ZT_CRITICAL_RISK:
        return (
            config.DENY,
            "critical_incident",
            (
                f"Principal is associated with active incident {c.incident['reference']} "
                f"({c.incident['classification']}, risk {c.incident_risk})."
            ),
        )
    return None


def _critical_threat(c):
    if c.max_threat_risk >= config.ZT_CRITICAL_RISK:
        threat_type = c.top_threat["threat_type"] if c.top_threat else "unknown"
        return (
            config.DENY,
            "critical_threat",
            f"An active critical threat ({threat_type}, risk {c.max_threat_risk}) involves this context.",
        )
    return None


def _subject_contained(c):
    if c.subject_contained:
        return (
            config.DENY,
            "subject_contained",
            "The principal has been contained by an automated response.",
        )
    return None


def _source_contained(c):
    if c.source_contained:
        return (
            config.DENY,
            "source_contained",
            f"Source address {c.source_ip} is blocked inside SentinelMesh.",
        )
    return None


def _device_isolated(c):
    if c.device_isolated:
        return (
            config.DENY,
            "device_isolated",
            "The device has been isolated by an automated response.",
        )
    return None


def _insufficient_privilege(c):
    if _rank(c.sensitivity) >= _rank(config.ZT_PRIVILEGED_SENSITIVITY):
        if c.subject_role not in config.PRIVILEGED_ROLES:
            return (
                config.DENY,
                "insufficient_privilege",
                (
                    f"Role {c.subject_role!r} is not permitted on a {c.sensitivity} resource; "
                    f"{sorted(config.PRIVILEGED_ROLES)} required."
                ),
            )
    return None


def _high_risk_on_sensitive_resource(c):
    if c.max_threat_risk >= config.ZT_HIGH_RISK and _at_least_sensitive(c):
        return (
            config.DENY,
            "high_risk_sensitive_resource",
            (
                f"Active threat risk {c.max_threat_risk} is too high for a "
                f"{c.sensitivity} resource."
            ),
        )
    return None


def _untrusted_device_on_sensitive_resource(c):
    if c.device_state == config.DEVICE_UNTRUSTED and _at_least_sensitive(c):
        return (
            config.DENY,
            "untrusted_device_sensitive_resource",
            f"Device is untrusted (trust {c.device_trust}) and the resource is {c.sensitivity}.",
        )
    return None


def _high_risk_incident(c):
    if c.incident is not None and c.incident_risk >= config.ZT_HIGH_RISK:
        return (
            config.STEP_UP,
            "high_risk_incident",
            (
                f"Active incident {c.incident['reference']} (risk {c.incident_risk}) "
                "requires additional verification."
            ),
        )
    return None


def _high_risk_threat(c):
    if c.max_threat_risk >= config.ZT_HIGH_RISK:
        return (
            config.STEP_UP,
            "high_risk_threat",
            f"Active threat risk {c.max_threat_risk} requires additional verification.",
        )
    return None


def _device_not_trusted(c):
    if c.device_state != config.DEVICE_TRUSTED:
        return (
            config.STEP_UP,
            "device_not_trusted",
            f"Device is {c.device_state} and must be verified before access.",
        )
    return None


def _elevated_risk(c):
    if c.max_threat_risk >= config.ZT_ELEVATED_RISK:
        return (
            config.STEP_UP,
            "elevated_risk",
            f"Active threat risk {c.max_threat_risk} is elevated; verification required.",
        )
    return None


def _privileged_resource_step_up(c):
    if _rank(c.sensitivity) >= _rank(config.ZT_PRIVILEGED_SENSITIVITY):
        return (
            config.STEP_UP,
            "privileged_resource",
            f"A {c.sensitivity} resource always requires re-verification, including for privileged roles.",
        )
    return None


POLICY_PRECEDENCE = (
    _identity_unauthenticated,
    _identity_unknown,
    _critical_incident,
    _critical_threat,
    # Containment sits below the incident and threat rules on purpose: those
    # describe *why* access is unsafe, while containment is the mechanism
    # derived from them. Reporting the cause is more useful to an analyst. It
    # still denies on its own once an incident is triaged away.
    _subject_contained,
    _source_contained,
    _device_isolated,
    _insufficient_privilege,
    _high_risk_on_sensitive_resource,
    _untrusted_device_on_sensitive_resource,
    _high_risk_incident,
    _high_risk_threat,
    _device_not_trusted,
    _elevated_risk,
    _privileged_resource_step_up,
)

DENY_POLICIES = (
    "identity_unauthenticated",
    "identity_unknown",
    "critical_incident",
    "critical_threat",
    "subject_contained",
    "source_contained",
    "device_isolated",
    "insufficient_privilege",
    "high_risk_sensitive_resource",
    "untrusted_device_sensitive_resource",
)

STEP_UP_POLICIES = (
    "high_risk_incident",
    "high_risk_threat",
    "device_not_trusted",
    "elevated_risk",
    "privileged_resource",
)

PRECEDENCE_NAMES = DENY_POLICIES + STEP_UP_POLICIES + ("trusted_baseline",)


def _factors(context: AccessContext) -> list:
    """Per-category evidence. Carries no credentials or payload contents."""
    return [
        {
            "category": "identity",
            "factor": "principal",
            "value": context.subject_username,
            "detail": (
                f"user_id={context.subject_user_id} role={context.subject_role!r} "
                f"authenticated={context.authenticated}"
            ),
        },
        {
            "category": "device",
            "factor": "device_trust",
            "value": context.device_state,
            "detail": (
                f"fingerprint={'present' if context.device_fingerprint else 'absent'} "
                f"trust={context.device_trust if context.device_trust is not None else 'n/a'}"
            ),
        },
        {
            "category": "threat",
            "factor": "max_threat_risk",
            "value": context.max_threat_risk,
            "detail": (
                f"{context.threat_count} active threat(s); highest is "
                f"{context.top_threat['threat_type']} at risk {context.max_threat_risk}"
                if context.top_threat
                else "no active threats in this context"
            ),
        },
        {
            "category": "incident",
            "factor": "active_incident",
            "value": context.incident["reference"] if context.incident else None,
            "detail": (
                f"{context.incident['classification']} risk={context.incident_risk} "
                f"status={context.incident['status']} "
                f"correlation_confidence={context.incident['correlation_confidence']}"
                if context.incident
                else "no active incident involves this context"
            ),
        },
        {
            "category": "resource",
            "factor": "sensitivity",
            "value": context.sensitivity,
            "detail": f"{context.resource} classified {context.sensitivity} by server policy",
        },
        {
            "category": "containment",
            "factor": "active_containment",
            "value": sorted(
                name
                for name, active in (
                    ("subject", context.subject_contained),
                    ("source", context.source_contained),
                    ("device", context.device_isolated),
                )
                if active
            ),
            "detail": "containment applied by the response engine inside SentinelMesh",
        },
    ]


def evaluate_access(context: AccessContext) -> AccessDecision:
    """Apply the policy to an authoritative context. Pure and deterministic."""
    for rule in POLICY_PRECEDENCE:
        outcome = rule(context)
        if outcome is not None:
            decision, policy, reason = outcome
            return AccessDecision(decision, policy, reason, _factors(context))

    return AccessDecision(
        config.ALLOW,
        "trusted_baseline",
        "Authenticated principal on a trusted device with no active threat or incident.",
        _factors(context),
    )


# --- context loading ---------------------------------------------------------

SUBJECT_SQL = "SELECT id, username, role, contained FROM users WHERE id = %s"

DEVICE_SQL = """
    SELECT trust_score, isolated
    FROM devices
    WHERE user_id = %(user_id)s AND device_fingerprint = %(fingerprint)s
"""

SOURCE_BLOCKED_SQL = "SELECT 1 FROM blocked_sources WHERE source_ip = %s::inet"

# One indexed pass over recent threats for this subject or address, capped, then
# the worst is taken in Python. Avoids a per-threat query.
ACTIVE_THREATS_SQL = """
    SELECT t.id, t.threat_type, t.risk_score, t.risk_level, t.severity, t.incident_id
    FROM threats t
    JOIN events e ON e.id = t.event_id
    WHERE t.detected_at > now() - make_interval(secs => %(window)s)
      AND ((%(user_id)s::bigint IS NOT NULL AND e.user_id = %(user_id)s::bigint)
        OR (%(source_ip)s::inet IS NOT NULL AND e.source_ip = %(source_ip)s::inet))
    ORDER BY t.risk_score DESC NULLS LAST, t.id DESC
    LIMIT %(limit)s
"""

# Semi-join rather than a join plus DISTINCT: only the worst active incident
# touching this context matters.
ACTIVE_INCIDENT_SQL = """
    SELECT i.id, i.classification, i.status, i.risk_score, i.severity, i.correlation_confidence
    FROM incidents i
    WHERE i.status = ANY (%(statuses)s::incident_status[])
      AND EXISTS (
            SELECT 1
            FROM threats t
            JOIN events e ON e.id = t.event_id
            WHERE t.incident_id = i.id
              AND ((%(user_id)s::bigint IS NOT NULL AND e.user_id = %(user_id)s::bigint)
                OR (%(source_ip)s::inet IS NOT NULL AND e.source_ip = %(source_ip)s::inet))
      )
    ORDER BY i.risk_score DESC, i.id DESC
    LIMIT 1
"""


def _reference(incident_id: int) -> str:
    return f"SM-{incident_id:03d}"


def load_access_context(conn, *, resource, subject_user_id, device_fingerprint, source_ip) -> AccessContext:
    """Assemble the context from authoritative records only.

    The caller supplies the subject id, the claimed device fingerprint, the
    resource and the observed address. Everything security-relevant -- role,
    device trust, threat risk, incident state, resource sensitivity -- is read
    here and cannot be asserted by the caller.
    """
    sensitivity = sensitivity_for(resource)
    authenticated = subject_user_id is not None

    username = role = None
    exists = subject_contained = False
    if authenticated:
        with conn.cursor() as cur:
            cur.execute(SUBJECT_SQL, (subject_user_id,))
            row = cur.fetchone()
        if row is not None:
            exists, username, role = True, row["username"], row["role"]
            subject_contained = row["contained"]

    device_state, device_trust, device_isolated = config.DEVICE_UNKNOWN, None, False
    if exists and isinstance(device_fingerprint, str) and device_fingerprint:
        with conn.cursor() as cur:
            cur.execute(DEVICE_SQL, {"user_id": subject_user_id, "fingerprint": device_fingerprint})
            row = cur.fetchone()
        if row is not None:
            device_trust = row["trust_score"]
            device_isolated = row["isolated"]
            device_state = (
                config.DEVICE_TRUSTED
                if device_trust >= config.RISK_DEVICE_TRUST_THRESHOLD
                else config.DEVICE_UNTRUSTED
            )

    source_contained = False
    if source_ip is not None:
        with conn.cursor() as cur:
            cur.execute(SOURCE_BLOCKED_SQL, (source_ip,))
            source_contained = cur.fetchone() is not None

    threats = []
    incident = None
    if exists or source_ip is not None:
        params = {
            "user_id": subject_user_id if exists else None,
            "source_ip": source_ip,
            "window": config.ZT_THREAT_WINDOW_SECONDS,
            "limit": config.ZT_CONTEXT_LIMIT,
        }
        with conn.cursor() as cur:
            cur.execute(ACTIVE_THREATS_SQL, params)
            threats = cur.fetchall()
        with conn.cursor() as cur:
            cur.execute(
                ACTIVE_INCIDENT_SQL,
                {
                    "user_id": params["user_id"],
                    "source_ip": source_ip,
                    "statuses": list(config.ZT_ACTIVE_INCIDENT_STATUSES),
                },
            )
            incident = cur.fetchone()

    scored = [int(t["risk_score"]) for t in threats if t["risk_score"] is not None]
    top = max(threats, key=lambda t: int(t["risk_score"] or 0)) if threats else None

    return AccessContext(
        resource=resource,
        sensitivity=sensitivity,
        authenticated=authenticated,
        subject_user_id=subject_user_id,
        subject_username=username,
        subject_role=role,
        subject_exists=exists,
        device_fingerprint=device_fingerprint,
        device_state=device_state,
        device_trust=device_trust,
        source_ip=source_ip,
        max_threat_risk=max(scored) if scored else 0,
        top_threat=(
            {
                "id": top["id"],
                "threat_type": top["threat_type"],
                "risk_score": int(top["risk_score"]) if top["risk_score"] is not None else None,
                "risk_level": top["risk_level"],
            }
            if top
            else None
        ),
        threat_count=len(threats),
        incident=(
            {
                "id": incident["id"],
                "reference": _reference(incident["id"]),
                "classification": incident["classification"],
                "status": incident["status"],
                "risk_score": int(incident["risk_score"]),
                "correlation_confidence": (
                    float(incident["correlation_confidence"])
                    if incident["correlation_confidence"] is not None
                    else None
                ),
            }
            if incident
            else None
        ),
        incident_risk=int(incident["risk_score"]) if incident else 0,
        subject_contained=subject_contained,
        source_contained=source_contained,
        device_isolated=device_isolated,
    )


# --- persistence -------------------------------------------------------------

RECORD_SQL = """
    INSERT INTO access_decisions (
        api_key, subject_user_id, subject_username, subject_role, authenticated,
        device_fingerprint, device_state, device_trust, source_ip, resource, sensitivity,
        decision, policy, reason, factors, max_threat_risk, incident_id, incident_risk
    ) VALUES (
        %(api_key)s, %(subject_user_id)s, %(subject_username)s, %(subject_role)s, %(authenticated)s,
        %(device_fingerprint)s, %(device_state)s, %(device_trust)s, %(source_ip)s::inet,
        %(resource)s, %(sensitivity)s,
        %(decision)s, %(policy)s, %(reason)s, %(factors)s, %(max_threat_risk)s,
        %(incident_id)s, %(incident_risk)s
    )
    RETURNING id, decided_at
"""


def record_decision(conn, context: AccessContext, decision: AccessDecision, api_key: str) -> dict:
    """Write the immutable audit record. Never updated after insert."""
    with conn.cursor() as cur:
        cur.execute(
            RECORD_SQL,
            {
                "api_key": api_key,
                "subject_user_id": context.subject_user_id if context.subject_exists else None,
                "subject_username": context.subject_username,
                "subject_role": context.subject_role,
                "authenticated": context.authenticated,
                "device_fingerprint": context.device_fingerprint,
                "device_state": context.device_state,
                "device_trust": context.device_trust,
                "source_ip": context.source_ip,
                "resource": context.resource,
                "sensitivity": context.sensitivity,
                "decision": decision.decision,
                "policy": decision.policy,
                "reason": decision.reason,
                "factors": Jsonb(decision.to_dict()),
                "max_threat_risk": context.max_threat_risk,
                "incident_id": context.incident["id"] if context.incident else None,
                "incident_risk": context.incident_risk if context.incident else None,
            },
        )
        row = cur.fetchone()

    log.info(
        "access decision",
        extra={
            "decision_id": row["id"],
            "decision": decision.decision,
            "policy": decision.policy,
            "subject_user_id": context.subject_user_id,
            "resource": context.resource,
            "api_key": api_key,
        },
    )
    return row
