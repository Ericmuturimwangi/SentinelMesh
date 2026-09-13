"""Detection dispatcher.

Runs every rule against one stored event and persists whatever fires. Each rule
executes inside its own savepoint, so a rule that raises rolls back only its own
work: the event stays stored and the remaining rules still run. Losing telemetry
is worse than losing one detection.
"""

import logging

from psycopg.types.json import Jsonb

from .rules import RULES

log = logging.getLogger("sentinelmesh.detection")

# The (event_id, threat_type) unique constraint is the idempotency key: each
# rule emits exactly one threat_type, so re-running detection over an event
# revises its verdict in place instead of accumulating duplicates.
UPSERT_SQL = """
    INSERT INTO threats (event_id, threat_type, severity, confidence, rule_id, evidence)
    VALUES (%(event_id)s, %(threat_type)s, %(severity)s, %(confidence)s, %(rule_id)s, %(evidence)s)
    ON CONFLICT (event_id, threat_type) DO UPDATE
        SET severity    = EXCLUDED.severity,
            confidence  = EXCLUDED.confidence,
            rule_id     = EXCLUDED.rule_id,
            evidence    = EXCLUDED.evidence,
            detected_at = now()
    RETURNING id
"""


def _persist(conn, event_id: int, detection) -> int:
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
            },
        )
        return cur.fetchone()["id"]


def run_detection(conn, event) -> list:
    """Evaluate every rule against one stored event, persisting what fires."""
    detections = []
    for rule in RULES:
        try:
            with conn.transaction():
                detection = rule(conn, event)
                if detection is None:
                    continue
                threat_id = _persist(conn, event["id"], detection)
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
            },
        )
        detections.append(detection)

    return detections
