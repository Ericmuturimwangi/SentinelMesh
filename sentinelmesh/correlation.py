"""Correlation and incident engine.

Answers one question only: *are these threats part of the same attack?* It does
not detect (that is rules.py), it does not score a single threat (risk.py), and
it takes no response action.

The decision functions -- link scoring, classification, incident risk -- are
pure and take already-loaded rows, so they are unit-testable without a database.
Only `correlate` touches PostgreSQL.
"""

import logging
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal

from psycopg.types.json import Jsonb

from . import config
from .risk import RiskFactor, level_for

log = logging.getLogger("sentinelmesh.correlation")

ONE = Decimal(1)
THREE_PLACES = Decimal("0.001")


@dataclass(frozen=True)
class LinkScore:
    confidence: Decimal
    signals: list

    def to_list(self) -> list:
        return self.signals


# --- pure: campaign identity -------------------------------------------------


def correlation_key_for(event) -> str:
    """The campaign an event belongs to.

    Source address first, deliberately: unauthenticated brute-force failures
    carry no user_id, so keying on identity would split them from the
    authenticated follow-up traffic from the same address and no multi-stage
    chain would ever form.
    """
    if event.get("source_ip") is not None:
        return f"ip:{event['source_ip']}"
    if event.get("user_id") is not None:
        return f"user:{event['user_id']}"
    return f"threat:event-{event['id']}"


# --- pure: link scoring ------------------------------------------------------


def score_link(incident, members, event, detection) -> LinkScore:
    """How confident are we that this threat joins that incident?

    Distinct from detection confidence: a rule may be certain SQL injection
    occurred while we are only moderately sure it is the same campaign.
    """
    signals = []
    total = Decimal(0)

    key = correlation_key_for(event)
    if key.startswith("ip:"):
        total += config.CORRELATION_WEIGHT_SAME_SOURCE
        signals.append(
            RiskFactor(
                "same_source",
                key.removeprefix("ip:"),
                float(config.CORRELATION_WEIGHT_SAME_SOURCE),
                "threat originates from the same source address as the incident",
            ).to_dict()
        )
    else:
        signals.append(RiskFactor("same_source", None, 0.0, "no source address to correlate on").to_dict())

    member_users = {m["user_id"] for m in members if m["user_id"] is not None}
    if event.get("user_id") is not None and event["user_id"] in member_users:
        total += config.CORRELATION_WEIGHT_SAME_USER
        signals.append(
            RiskFactor(
                "same_user",
                event["user_id"],
                float(config.CORRELATION_WEIGHT_SAME_USER),
                "same principal is already implicated in this incident",
            ).to_dict()
        )
    else:
        signals.append(
            RiskFactor("same_user", event.get("user_id"), 0.0, "principal not already in this incident").to_dict()
        )

    elapsed = abs((event["occurred_at"] - incident["last_activity_at"]).total_seconds())
    window = config.CORRELATION_WINDOW_SECONDS
    proximity = max(Decimal(0), ONE - (Decimal(str(elapsed)) / Decimal(window)))
    temporal = (config.CORRELATION_WEIGHT_TEMPORAL_MAX * proximity).quantize(THREE_PLACES, ROUND_HALF_UP)
    total += temporal
    signals.append(
        RiskFactor(
            "temporal_proximity",
            int(elapsed),
            float(temporal),
            f"{int(elapsed)}s after the incident's last activity, within a {window}s window",
        ).to_dict()
    )

    known_stages = {
        config.ATTACK_STAGES[m["threat_type"]][0] for m in members if m["threat_type"] in config.ATTACK_STAGES
    }
    new_stage = config.ATTACK_STAGES.get(detection["threat_type"], (None, None))[0]
    if new_stage is not None and known_stages and new_stage not in known_stages:
        total += config.CORRELATION_WEIGHT_PROGRESSION
        signals.append(
            RiskFactor(
                "attack_progression",
                config.ATTACK_STAGES[detection["threat_type"]][1],
                float(config.CORRELATION_WEIGHT_PROGRESSION),
                "threat advances the campaign into a new attack stage",
            ).to_dict()
        )
    else:
        signals.append(
            RiskFactor("attack_progression", None, 0.0, "threat does not open a new attack stage").to_dict()
        )

    confidence = min(max(total, config.CORRELATION_CONFIDENCE_MIN), config.CORRELATION_CONFIDENCE_MAX)
    return LinkScore(confidence=confidence.quantize(THREE_PLACES, ROUND_HALF_UP), signals=signals)


# --- pure: classification ----------------------------------------------------


def classify(members) -> tuple:
    """Return (classification, ordered stage names, stages were chronological)."""
    # Ordered on the attack timeline (occurred_at), not on when we noticed
    # (detected_at): stage ordering must not depend on ingest latency.
    first_seen = {}
    for member in members:
        stage = config.ATTACK_STAGES.get(member["threat_type"])
        if stage is None:
            continue
        number, _name = stage
        happened = member["occurred_at"]
        if number not in first_seen or happened < first_seen[number]:
            first_seen[number] = happened

    if not first_seen:
        return config.CLASSIFICATION_UNCLASSIFIED, [], False

    ordered = sorted(first_seen)
    names = [config.ATTACK_STAGES_BY_NUMBER[n] for n in ordered]

    # Stages must have been reached in order for this to be a progression.
    # Without this check three simultaneous detections would read as multi-stage.
    chronological = all(first_seen[a] <= first_seen[b] for a, b in zip(ordered, ordered[1:]))

    if len(ordered) >= config.INCIDENT_MULTI_STAGE_MIN_STAGES and chronological:
        return config.CLASSIFICATION_MULTI_STAGE, names, True

    return config.CLASSIFICATION_BY_STAGE.get(ordered[-1], config.CLASSIFICATION_UNCLASSIFIED), names, chronological


# --- pure: incident risk -----------------------------------------------------


def calculate_incident_risk(members, classification: str, confidence: Decimal | None):
    """Campaign risk: the worst member, plus what a single threat cannot see.

    Never an average -- averaging lets two mild threats hide a severe one --
    and never a sum, which would leave the 0-100 model behind.
    """
    scored = [int(m["risk_score"]) for m in members if m["risk_score"] is not None]
    base = max(scored) if scored else 0

    factors = [
        RiskFactor(
            "highest_threat_risk",
            base,
            base,
            f"worst of {len(members)} member threat(s) sets the floor at {base}",
        )
    ]

    distinct_types = {m["threat_type"] for m in members}
    breadth = min(
        (len(distinct_types) - 1) * config.INCIDENT_BREADTH_POINTS_PER_TYPE,
        config.INCIDENT_BREADTH_MAX_POINTS,
    )
    factors.append(
        RiskFactor(
            "threat_type_breadth",
            len(distinct_types),
            max(breadth, 0),
            f"{len(distinct_types)} distinct threat type(s) in this campaign",
        )
    )

    progression = config.INCIDENT_PROGRESSION_POINTS if classification == config.CLASSIFICATION_MULTI_STAGE else 0
    factors.append(
        RiskFactor(
            "attack_progression",
            classification,
            progression,
            "campaign advanced through multiple attack stages"
            if progression
            else "campaign has not progressed through multiple stages",
        )
    )

    strong = confidence is not None and confidence >= config.CORRELATION_STRONG_THRESHOLD
    factors.append(
        RiskFactor(
            "correlation_strength",
            float(confidence) if confidence is not None else None,
            config.INCIDENT_STRONG_CORRELATION_POINTS if strong else 0,
            "members are strongly correlated" if strong else "correlation is not strong enough to add risk",
        )
    )

    # Phase 3 already folds actor privilege and resource sensitivity into every
    # member threat's score. Counting them again here would be double-counting
    # the same underlying signal, so they are reported at zero.
    factors.append(
        RiskFactor(
            "privileged_identity",
            None,
            0,
            "already represented in member threat scores, not counted twice",
        )
    )
    factors.append(
        RiskFactor(
            "resource_sensitivity",
            None,
            0,
            "already represented in member threat scores, not counted twice",
        )
    )

    subtotal = sum(f.contribution for f in factors)
    score = min(max(subtotal, config.RISK_MIN_SCORE), config.RISK_MAX_SCORE)
    if score != subtotal:
        factors.append(
            RiskFactor(
                "bounds_clamp",
                subtotal,
                score - subtotal,
                f"raw total {subtotal} clamped into {config.RISK_MIN_SCORE}-{config.RISK_MAX_SCORE}",
            )
        )

    return score, level_for(score), factors


# --- pure: narrative ---------------------------------------------------------


def describe(members, classification: str, stage_names, confidence: Decimal | None, key: str) -> str:
    times = [m["occurred_at"] for m in members]
    span = int((max(times) - min(times)).total_seconds()) if len(times) > 1 else 0
    types = sorted({m["threat_type"] for m in members})
    source = key.removeprefix("ip:") if key.startswith("ip:") else key

    lines = [
        f"{len(members)} threat(s) correlated from {source} within {span} seconds.",
        "Threat types observed: " + ", ".join(types) + ".",
    ]
    if classification == config.CLASSIFICATION_MULTI_STAGE and len(stage_names) > 1:
        lines.append("The attack progressed from " + " to ".join(stage_names) + ".")
    if confidence is not None:
        strength = "HIGH" if confidence >= config.CORRELATION_STRONG_THRESHOLD else "MODERATE"
        lines.append(f"Correlation confidence: {strength} ({confidence}).")
    return " ".join(lines)


def title_for(classification: str, key: str) -> str:
    readable = classification.replace("_", " ").capitalize()
    source = key.removeprefix("ip:") if key.startswith("ip:") else key
    return f"{readable} from {source}"


# --- database orchestration --------------------------------------------------

FIND_SQL = """
    SELECT id, correlation_key, last_activity_at, correlation_confidence
    FROM incidents
    WHERE correlation_key = %s AND correlating
"""

CREATE_SQL = """
    INSERT INTO incidents (title, severity, risk_score, status, correlation_key,
                           classification, last_activity_at, correlating)
    VALUES (%(title)s, 'low', 0, 'open', %(key)s, %(classification)s, %(activity)s, true)
    ON CONFLICT (correlation_key) WHERE correlating DO NOTHING
    RETURNING id, correlation_key, last_activity_at, correlation_confidence
"""

MEMBERS_SQL = """
    SELECT t.id, t.threat_type, t.severity, t.confidence, t.detected_at,
           t.risk_score, t.risk_level, t.rule_id, t.evidence,
           e.id AS event_id, e.event_type, e.occurred_at, e.user_id, e.source_ip
    FROM threats t
    JOIN events e ON e.id = t.event_id
    WHERE t.incident_id = %s
    ORDER BY t.detected_at, t.id
"""

REFRESH_SQL = """
    UPDATE incidents
    SET title                  = %(title)s,
        classification         = %(classification)s,
        risk_score             = %(risk_score)s,
        severity               = %(severity)s,
        risk_factors           = %(risk_factors)s,
        correlation_confidence = %(confidence)s,
        correlation_factors    = %(correlation_factors)s,
        last_activity_at       = GREATEST(last_activity_at, %(activity)s)
    WHERE id = %(id)s
"""


def _load_members(conn, incident_id: int) -> list:
    with conn.cursor() as cur:
        cur.execute(MEMBERS_SQL, (incident_id,))
        return cur.fetchall()


def correlate(conn, event, threat_id: int, detection: dict) -> dict:
    """Place one threat into an incident, then refresh that incident's verdict."""
    key = correlation_key_for(event)

    # Serialises find-or-create for this campaign only. Held until COMMIT, so
    # two concurrent ingests cannot both conclude that no incident exists.
    # Different keys are unaffected and still run in parallel.
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (key,))

    with conn.cursor() as cur:
        cur.execute("SELECT incident_id FROM threats WHERE id = %s", (threat_id,))
        existing_incident = cur.fetchone()["incident_id"]

    if existing_incident is not None:
        # Reprocessing an already-correlated threat must not move it.
        incident_id, link = existing_incident, None
    else:
        incident_id, link = _find_or_create(conn, key, event, detection)
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE threats SET incident_id = %s WHERE id = %s AND incident_id IS NULL",
                (incident_id, threat_id),
            )

    members = _load_members(conn, incident_id)
    summary = _refresh(conn, incident_id, key, members, link)

    log.info(
        "threat correlated",
        extra={
            "incident_id": incident_id,
            "threat_id": threat_id,
            "correlation_key": key,
            "classification": summary["classification"],
            "member_count": len(members),
        },
    )
    return summary | {"incident_id": incident_id}


def _find_or_create(conn, key: str, event, detection: dict):
    with conn.cursor() as cur:
        cur.execute(FIND_SQL, (key,))
        candidate = cur.fetchone()

    if candidate is not None:
        elapsed = abs((event["occurred_at"] - candidate["last_activity_at"]).total_seconds())
        if elapsed <= config.CORRELATION_WINDOW_SECONDS:
            members = _load_members(conn, candidate["id"])
            return candidate["id"], score_link(candidate, members, event, detection)

        # The campaign went quiet for longer than the window, so this is a new
        # one. The old incident stops accumulating but stays open for triage --
        # this is not an automatic closure.
        with conn.cursor() as cur:
            cur.execute("UPDATE incidents SET correlating = false WHERE id = %s", (candidate["id"],))

    with conn.cursor() as cur:
        cur.execute(
            CREATE_SQL,
            {
                "title": title_for(config.CLASSIFICATION_UNCLASSIFIED, key),
                "key": key,
                "classification": config.CLASSIFICATION_UNCLASSIFIED,
                "activity": event["occurred_at"],
            },
        )
        created = cur.fetchone()

    if created is not None:
        return created["id"], None

    # Lost the race despite the lock (belt and braces): join the winner.
    with conn.cursor() as cur:
        cur.execute(FIND_SQL, (key,))
        winner = cur.fetchone()
    members = _load_members(conn, winner["id"])
    return winner["id"], score_link(winner, members, event, detection)


def _refresh(conn, incident_id: int, key: str, members, link: LinkScore | None) -> dict:
    with conn.cursor() as cur:
        cur.execute("SELECT correlation_confidence, correlation_factors FROM incidents WHERE id = %s", (incident_id,))
        current = cur.fetchone()

    # The incident keeps the strongest link ever observed: that is the claim
    # being made about whether these threats belong together.
    confidence = current["correlation_confidence"]
    signals = current["correlation_factors"].get("signals", [])
    if link is not None and (confidence is None or link.confidence > confidence):
        confidence, signals = link.confidence, link.to_list()

    classification, stage_names, _ordered = classify(members)
    score, level, factors = calculate_incident_risk(members, classification, confidence)
    explanation = describe(members, classification, stage_names, confidence, key)
    # The window slides along the attack timeline. Using detected_at here would
    # compare a server clock against client-asserted event times and every
    # replayed or batched event would look stale.
    latest = max(m["occurred_at"] for m in members)

    correlation_factors = {
        "model_version": config.CORRELATION_MODEL_VERSION,
        "correlation_key": key,
        "explanation": explanation,
        "window_seconds": config.CORRELATION_WINDOW_SECONDS,
        "attack_stages": stage_names,
        "signals": signals,
    }

    with conn.cursor() as cur:
        cur.execute(
            REFRESH_SQL,
            {
                "id": incident_id,
                "title": title_for(classification, key),
                "classification": classification,
                "risk_score": score,
                "severity": level,
                "risk_factors": Jsonb(
                    {
                        "model_version": config.CORRELATION_MODEL_VERSION,
                        "score": score,
                        "level": level,
                        "factors": [f.to_dict() for f in factors],
                    }
                ),
                "confidence": confidence,
                "correlation_factors": Jsonb(correlation_factors),
                "activity": latest,
            },
        )

    return {
        "classification": classification,
        "risk_score": score,
        "risk_level": level,
        "correlation_confidence": float(confidence) if confidence is not None else None,
        "threat_count": len(members),
    }


# --- derived: timeline -------------------------------------------------------


def build_timeline(conn, incident_id: int) -> list:
    """Ordered attack chain, derived from member events and threats.

    Nothing here is stored: duplicating it would let the incident drift out of
    step with the threats it is built from.
    """
    entries = []
    for member in _load_members(conn, incident_id):
        entries.append(
            {
                "at": member["occurred_at"].isoformat(),
                "kind": "event",
                "event_id": member["event_id"],
                "detail": f"{member['event_type']} from {member['source_ip']}",
            }
        )
        entries.append(
            {
                "at": member["detected_at"].isoformat(),
                "kind": "detection",
                "threat_id": member["id"],
                "detail": (
                    f"{member['threat_type']} detected by {member['rule_id']} "
                    f"(risk {int(member['risk_score']) if member['risk_score'] is not None else 'n/a'})"
                ),
            }
        )
    return sorted(entries, key=lambda e: (e["at"], e["kind"]))
