"""Risk scoring.

`calculate_threat_risk` is a pure function: same detection, event and context in,
same score out, with no database, Flask or HTTP involvement. Everything it needs
from the database is gathered once per event by `load_risk_context`, so the
scoring model itself stays unit-testable and reusable by later phases.

The model, in one line:

    score = clamp(baseline(severity) * confidence_factor + independent_context)

Severity and confidence describe the same detection, so confidence *scales* the
severity baseline rather than adding to it. Only signals the detection did not
already use -- who the actor is, what device they came from, what they reached,
what else they have tripped -- are added on top.
"""

from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

from . import config

ONE = Decimal(1)


@dataclass(frozen=True)
class RiskFactor:
    factor: str
    value: object
    contribution: int
    detail: str

    def to_dict(self) -> dict:
        return {
            "factor": self.factor,
            "value": self.value,
            "contribution": self.contribution,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class RiskContext:
    """Authoritative context, read from server-side records only."""

    actor_role: str | None = None
    device_trust: Decimal | None = None
    device_resolved: bool = False
    resource_sensitive: bool = False
    prior_threat_types: int = 0


@dataclass(frozen=True)
class RiskResult:
    score: int
    level: str
    factors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "model_version": config.RISK_MODEL_VERSION,
            "score": self.score,
            "level": self.level,
            "factors": [f.to_dict() for f in self.factors],
        }


def _as_decimal(value) -> Decimal:
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("confidence is not a number") from None


def level_for(score: int) -> str:
    for lower, upper, label in config.RISK_LEVEL_BANDS:
        if lower <= score <= upper:
            return label
    raise ValueError(f"score {score} falls outside every configured band")


def _confidence_factor(confidence: Decimal) -> Decimal:
    floor = config.RISK_CONFIDENCE_FLOOR
    return floor + (ONE - floor) * confidence


def _identity_factor(context: RiskContext) -> RiskFactor:
    role = context.actor_role
    points = config.RISK_ROLE_POINTS.get(role, 0) if role else 0
    detail = (
        f"actor holds the {role!r} role"
        if role
        else "no authenticated principal, so no privilege weighting applies"
    )
    return RiskFactor("privileged_identity", role, points, detail)


def _device_factor(event, context: RiskContext) -> RiskFactor:
    if event.get("user_id") is None:
        return RiskFactor("device_trust", None, 0, "no principal, so device trust is not applicable")

    if not context.device_resolved:
        return RiskFactor(
            "device_trust",
            None,
            config.RISK_UNKNOWN_DEVICE_POINTS,
            "event did not resolve to a known device for this user",
        )

    trust = context.device_trust
    if trust is not None and trust < config.RISK_DEVICE_TRUST_THRESHOLD:
        return RiskFactor(
            "device_trust",
            float(trust),
            config.RISK_UNTRUSTED_DEVICE_POINTS,
            f"device trust {trust} is below the {config.RISK_DEVICE_TRUST_THRESHOLD} threshold",
        )
    return RiskFactor("device_trust", float(trust), 0, f"device trust {trust} meets the threshold")


def _resource_factor(detection, context: RiskContext) -> RiskFactor:
    # The privileged-access rule fires *because* the resource is sensitive, so
    # scoring sensitivity again would count the same signal twice. It remains
    # independent information for any other threat type on the same resource.
    if detection.threat_type == config.THREAT_PRIVILEGED_ACCESS:
        return RiskFactor(
            "resource_sensitivity",
            True,
            0,
            "already represented by this threat type, so not counted twice",
        )
    if not context.resource_sensitive:
        return RiskFactor("resource_sensitivity", False, 0, "resource is not classified as sensitive")
    return RiskFactor(
        "resource_sensitivity",
        True,
        config.RISK_SENSITIVE_RESOURCE_POINTS,
        "target path is classified as a privileged resource",
    )


def _escalation_factor(context: RiskContext) -> RiskFactor:
    count = max(context.prior_threat_types, 0)
    points = min(count * config.RISK_ESCALATION_POINTS_PER_TYPE, config.RISK_ESCALATION_MAX_POINTS)
    detail = (
        f"{count} other threat type(s) already seen from this source address"
        if count
        else "no other threat types seen from this source address"
    )
    return RiskFactor("threat_escalation", count, points, detail)


def calculate_threat_risk(detection, event, context: RiskContext | None = None) -> RiskResult:
    """Score one detection. Deterministic, and free of any I/O."""
    context = context or RiskContext()

    if detection.severity not in config.RISK_SEVERITY_BASELINE:
        raise ValueError(f"unscoreable severity: {detection.severity!r}")

    baseline = config.RISK_SEVERITY_BASELINE[detection.severity]

    # Confidence is constrained by a database CHECK, but this is scoring logic
    # applied to rule output, so it does not assume the caller is well behaved.
    confidence = min(max(_as_decimal(detection.confidence), Decimal(0)), ONE)
    weighted = int(
        (Decimal(baseline) * _confidence_factor(confidence)).quantize(ONE, rounding=ROUND_HALF_UP)
    )

    factors = [
        RiskFactor(
            "threat_severity",
            detection.severity,
            baseline,
            f"{detection.severity} severity establishes a baseline of {baseline}",
        ),
        RiskFactor(
            "detection_confidence",
            float(confidence),
            weighted - baseline,
            f"confidence {confidence} scales the baseline to {weighted}",
        ),
        _identity_factor(context),
        _device_factor(event, context),
        _resource_factor(detection, context),
        _escalation_factor(context),
    ]

    subtotal = sum(f.contribution for f in factors)
    score = min(max(subtotal, config.RISK_MIN_SCORE), config.RISK_MAX_SCORE)
    if score != subtotal:
        # Recorded as a factor so the contributions always sum to the score.
        factors.append(
            RiskFactor(
                "bounds_clamp",
                subtotal,
                score - subtotal,
                f"raw total {subtotal} clamped into {config.RISK_MIN_SCORE}-{config.RISK_MAX_SCORE}",
            )
        )

    return RiskResult(score=score, level=level_for(score), factors=factors)


# --- context loading ---------------------------------------------------------

DEVICE_SQL = """
    SELECT trust_score
    FROM devices
    WHERE user_id = %(user_id)s AND device_fingerprint = %(fingerprint)s
"""

ESCALATION_SQL = """
    SELECT count(DISTINCT t.threat_type) AS types
    FROM threats t
    JOIN events e ON e.id = t.event_id
    WHERE e.source_ip = %(source_ip)s::inet
      AND e.id <> %(event_id)s
      AND t.detected_at > now() - make_interval(secs => %(window)s)
"""


def load_risk_context(conn, event) -> RiskContext:
    """Gather authoritative context once per event, not once per rule."""
    metadata = event["metadata"] if isinstance(event.get("metadata"), dict) else {}

    role = None
    if event.get("user_id") is not None:
        with conn.cursor() as cur:
            cur.execute("SELECT role FROM users WHERE id = %s", (event["user_id"],))
            row = cur.fetchone()
            role = row["role"] if row else None

    # The fingerprint is a claim; the trust score behind it is not. Scoping the
    # lookup to the event's own user means a claimed fingerprint belonging to
    # somebody else simply fails to resolve.
    device_trust, device_resolved = None, False
    fingerprint = metadata.get(config.DEVICE_FINGERPRINT_KEY)
    if event.get("user_id") is not None and isinstance(fingerprint, str) and fingerprint:
        with conn.cursor() as cur:
            cur.execute(DEVICE_SQL, {"user_id": event["user_id"], "fingerprint": fingerprint})
            row = cur.fetchone()
            if row is not None:
                device_trust, device_resolved = row["trust_score"], True

    path = metadata.get("path")
    resource_sensitive = isinstance(path, str) and path.startswith(config.PRIVILEGED_PATH_PREFIXES)

    prior_types = 0
    if event.get("source_ip") is not None:
        with conn.cursor() as cur:
            cur.execute(
                ESCALATION_SQL,
                {
                    "source_ip": str(event["source_ip"]),
                    "event_id": event["id"],
                    "window": config.RISK_ESCALATION_WINDOW_SECONDS,
                },
            )
            prior_types = cur.fetchone()["types"]

    return RiskContext(
        actor_role=role,
        device_trust=device_trust,
        device_resolved=device_resolved,
        resource_sensitive=resource_sensitive,
        prior_threat_types=prior_types,
    )
