"""Detection dispatcher.

Runs every rule against one stored event and persists whatever fires. Each rule
executes inside its own savepoint, so a rule that raises rolls back only its own
work: the event stays stored and the remaining rules still run. Losing telemetry
is worse than losing one detection.
"""

import logging

from psycopg.types.json import Jsonb

from .correlation import correlate
from .response import respond_to_incident
from .risk import calculate_threat_risk, load_risk_context
from .rules import RULES

log = logging.getLogger("sentinelmesh.detection")

# The (event_id, threat_type) unique constraint is the idempotency key: each
# rule emits exactly one threat_type, so re-running detection over an event
# revises its verdict in place instead of accumulating duplicates.
UPSERT_SQL = """
    INSERT INTO threats (event_id, threat_type, severity, confidence, rule_id, evidence,
                         risk_score, risk_level, risk_factors, risk_calculated_at)
    VALUES (%(event_id)s, %(threat_type)s, %(severity)s, %(confidence)s, %(rule_id)s, %(evidence)s,
            %(risk_score)s, %(risk_level)s, %(risk_factors)s, now())
    ON CONFLICT (event_id, threat_type) DO UPDATE
        SET severity           = EXCLUDED.severity,
            confidence         = EXCLUDED.confidence,
            rule_id            = EXCLUDED.rule_id,
            evidence           = EXCLUDED.evidence,
            risk_score         = EXCLUDED.risk_score,
            risk_level         = EXCLUDED.risk_level,
            risk_factors       = EXCLUDED.risk_factors,
            risk_calculated_at = now(),
            detected_at        = now()
    RETURNING id
"""


def _persist(conn, event_id: int, detection, risk) -> int:
    with conn.cursor() as cur:
        cur.execute(
            UPSERT_SQL,
            {
                "event_id": event_id,
                "threat_type": detection.threat_type,
                "severity": detection.severity,
                "confidence": detection.confidence,
                "rule_id": detection.rule_id,
                "evidence": Jsonb({**detection.evidence, "reason": detection.reason}),
                "risk_score": risk.score,
                "risk_level": risk.level,
                "risk_factors": Jsonb(risk.to_dict()),
            },
        )
        return cur.fetchone()["id"]


def run_detection(conn, event) -> list:
    """Evaluate every rule against one stored event, scoring and persisting hits.

    Risk context is loaded at most once per event, and only if something fires,
    so an event that produces no threats costs no extra queries. Because it is
    loaded before the first threat is written, every rule on one event scores
    against the same context and the outcome does not depend on rule order.
    """
    outcomes = []
    context = None
    for rule in RULES:
        try:
            with conn.transaction():
                detection = rule(conn, event)
                if detection is None:
                    continue
                if context is None:
                    context = load_risk_context(conn, event)
                risk = calculate_threat_risk(detection, event, context)
                threat_id = _persist(conn, event["id"], detection, risk)
                incident = correlate(conn, event, threat_id, detection.summary())
                # Containment runs in the same transaction as the threat and
                # incident it answers to. Every action is internal SentinelMesh
                # state, so this is atomic: there is no window in which a
                # response claims containment for a threat that then rolls back.
                # Its own savepoint means a response fault cannot discard the
                # detection -- losing telemetry is worse than missing one
                # containment, and the incident stays visible to the SOC.
                try:
                    with conn.transaction():
                        response = respond_to_incident(
                            conn, incident["incident_id"], actor="engine", threat_id=threat_id
                        )
                except Exception:
                    log.exception(
                        "automated response failed",
                        extra={"event_id": event["id"], "incident_id": incident["incident_id"]},
                    )
                    response = None
        except Exception:
            log.exception("detection rule failed", extra={"rule": rule.__name__, "event_id": event["id"]})
            continue

        log.info(
            "threat detected",
            extra={
                "rule_id": detection.rule_id,
                "threat_id": threat_id,
                "threat_type": detection.threat_type,
                "event_id": event["id"],
                "risk_score": risk.score,
                "risk_level": risk.level,
                "incident_id": incident["incident_id"],
            },
        )
        outcomes.append(
            detection.summary()
            | {
                "threat_id": threat_id,
                "risk_score": risk.score,
                "risk_level": risk.level,
                "incident": incident,
                "response": response,
            }
        )

    return outcomes
