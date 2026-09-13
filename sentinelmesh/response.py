"""Automated response engine.

Answers one question: *what should SentinelMesh do because of the security
state?* That is separate from zero trust, which answers whether one access
request should be allowed. A critical incident makes Phase 5 deny access and
makes this engine contain the campaign; they are two decisions, not one.

`evaluate_response` is pure -- context in, plan out, no writes. Execution is a
separate layer, and every action is applied and audited independently so one
failure cannot be reported as overall success.

CONTAINMENT IS INTERNAL. Every action changes SentinelMesh's own authoritative
state, which the zero-trust engine then enforces on later access decisions.
Nothing here touches a firewall, a router, an operating system, a process, or
any external system.
"""

import logging
from dataclasses import dataclass, field

from psycopg.types.json import Jsonb

from . import config
from .risk import level_for

log = logging.getLogger("sentinelmesh.response")


@dataclass(frozen=True)
class ResponseContext:
    incident_id: int
    incident_risk: int = 0
    incident_classification: str | None = None
    incident_status: str | None = None
    highest_threat_risk: int = 0
    threat_types: tuple = ()
    threat_count: int = 0
    affected_user_ids: tuple = ()
    affected_usernames: tuple = ()
    source_ips: tuple = ()
    device_ids: tuple = ()
    device_fingerprints: tuple = ()


@dataclass(frozen=True)
class ResponsePlan:
    actions: tuple
    policy: str
    reason: str
    severity: str
    risk: int
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "model_version": config.RESPONSE_MODEL_VERSION,
            "policy": self.policy,
            "reason": self.reason,
            "severity": self.severity,
            "risk": self.risk,
            "actions": list(self.actions),
            "evidence": self.evidence,
        }


def _containment_actions(context: ResponseContext) -> tuple:
    """Containment limited to entities legitimately part of this incident."""
    actions = [config.ACTION_ALERT]
    if context.affected_user_ids:
        actions.append(config.ACTION_CONTAIN_SUBJECT)
    if context.source_ips:
        actions.append(config.ACTION_BLOCK_SOURCE)
    if context.device_ids:
        actions.append(config.ACTION_ISOLATE_DEVICE)
    return tuple(actions)


def evaluate_response(context: ResponseContext) -> ResponsePlan:
    """Decide the response plan. Pure, deterministic, no I/O.

    Precedence, first match wins:
      1. critical incident   2. critical threat
      3. high incident       4. high threat
      5. medium              6. low

    An incident outranks a lone threat at the same tier: three correlated
    threats forming a campaign warrant more than one isolated detection.
    """
    evidence = {
        "incident_risk": context.incident_risk,
        "incident_classification": context.incident_classification,
        "highest_threat_risk": context.highest_threat_risk,
        "threat_types": list(context.threat_types),
        "threat_count": context.threat_count,
        "affected_users": list(context.affected_usernames),
        "source_ips": list(context.source_ips),
        "devices": list(context.device_fingerprints),
    }
    driving = max(context.incident_risk, context.highest_threat_risk)

    if context.incident_risk >= config.ZT_CRITICAL_RISK:
        return ResponsePlan(
            _containment_actions(context),
            config.RESPONSE_POLICY_CRITICAL_INCIDENT,
            (
                f"Incident risk {context.incident_risk} ({context.incident_classification}) is critical; "
                "containing the campaign inside SentinelMesh."
            ),
            level_for(context.incident_risk),
            context.incident_risk,
            evidence,
        )

    if context.highest_threat_risk >= config.ZT_CRITICAL_RISK:
        # No device isolation: a lone critical threat is not yet a campaign, so
        # containment stays on the principal and the address it came from.
        actions = tuple(a for a in _containment_actions(context) if a != config.ACTION_ISOLATE_DEVICE)
        return ResponsePlan(
            actions,
            config.RESPONSE_POLICY_CRITICAL_THREAT,
            f"A critical threat (risk {context.highest_threat_risk}) requires immediate containment.",
            level_for(context.highest_threat_risk),
            context.highest_threat_risk,
            evidence,
        )

    if context.incident_risk >= config.ZT_HIGH_RISK:
        return ResponsePlan(
            (config.ACTION_ALERT, config.ACTION_REQUIRE_STEP_UP),
            config.RESPONSE_POLICY_HIGH_INCIDENT,
            (
                f"Incident risk {context.incident_risk} is high; escalating without containment "
                "while the campaign is still being established."
            ),
            level_for(context.incident_risk),
            context.incident_risk,
            evidence,
        )

    if context.highest_threat_risk >= config.ZT_HIGH_RISK:
        return ResponsePlan(
            (config.ACTION_ALERT, config.ACTION_REQUIRE_STEP_UP),
            config.RESPONSE_POLICY_HIGH_THREAT,
            (
                f"A high-risk threat (risk {context.highest_threat_risk}) warrants step-up verification, "
                "not containment of the principal."
            ),
            level_for(context.highest_threat_risk),
            context.highest_threat_risk,
            evidence,
        )

    if driving >= config.ZT_ELEVATED_RISK:
        # The audit record is the monitoring: no separate logging pipeline is
        # invented for a tier that does not need containment.
        return ResponsePlan(
            (config.ACTION_ALERT,),
            config.RESPONSE_POLICY_MEDIUM,
            f"Risk {driving} is elevated; recording an alert for analyst review without containment.",
            level_for(driving),
            driving,
            evidence,
        )

    return ResponsePlan(
        (),
        config.RESPONSE_POLICY_LOW,
        f"Risk {driving} is low; no containment and no alert noise.",
        level_for(driving),
        driving,
        evidence,
    )


# --- context loading ---------------------------------------------------------

INCIDENT_SQL = """
    SELECT id, classification, status, risk_score
    FROM incidents
    WHERE id = %s
"""

MEMBERS_SQL = """
    SELECT t.threat_type, t.risk_score, e.user_id, e.source_ip, u.username
    FROM threats t
    JOIN events e ON e.id = t.event_id
    LEFT JOIN users u ON u.id = e.user_id
    WHERE t.incident_id = %(incident_id)s
    ORDER BY t.risk_score DESC NULLS LAST, t.id
    LIMIT %(limit)s
"""

# A device is in scope only when it belongs to the event's own principal AND was
# named by that event. This is what keeps isolation from reaching devices that
# merely happen to belong to the user but took no part in the incident.
DEVICES_SQL = """
    SELECT DISTINCT d.id, d.device_fingerprint
    FROM devices d
    JOIN events e ON e.user_id = d.user_id
                 AND e.metadata ->> 'device_fingerprint' = d.device_fingerprint
    JOIN threats t ON t.event_id = e.id
    WHERE t.incident_id = %(incident_id)s
    LIMIT %(limit)s
"""


def load_response_context(conn, incident_id: int) -> ResponseContext | None:
    with conn.cursor() as cur:
        cur.execute(INCIDENT_SQL, (incident_id,))
        incident = cur.fetchone()
    if incident is None:
        return None

    params = {"incident_id": incident_id, "limit": config.RESPONSE_CONTEXT_LIMIT}
    with conn.cursor() as cur:
        cur.execute(MEMBERS_SQL, params)
        members = cur.fetchall()
    with conn.cursor() as cur:
        cur.execute(DEVICES_SQL, params)
        devices = cur.fetchall()

    scored = [int(m["risk_score"]) for m in members if m["risk_score"] is not None]
    user_ids = sorted({m["user_id"] for m in members if m["user_id"] is not None})
    usernames = sorted({m["username"] for m in members if m["username"]})
    sources = sorted({str(m["source_ip"]) for m in members if m["source_ip"] is not None})

    return ResponseContext(
        incident_id=incident_id,
        incident_risk=int(incident["risk_score"]),
        incident_classification=incident["classification"],
        incident_status=incident["status"],
        highest_threat_risk=max(scored) if scored else 0,
        threat_types=tuple(sorted({m["threat_type"] for m in members})),
        threat_count=len(members),
        affected_user_ids=tuple(user_ids),
        affected_usernames=tuple(usernames),
        source_ips=tuple(sources),
        device_ids=tuple(sorted(d["id"] for d in devices)),
        device_fingerprints=tuple(sorted(d["device_fingerprint"] for d in devices)),
    )


# --- action executors --------------------------------------------------------
#
# Each returns (applied, detail). applied=False means the state was already in
# effect, so nothing was changed. Raising signals a genuine failure.


def _alert(conn, context):
    # The audit row itself is the alert: it is what the SOC reads.
    return True, {"alerted": True}


def _require_step_up(conn, context):
    # Recorded as a directive. Enforcement is Phase 5's: while this incident is
    # active, its high_risk_incident rule returns STEP_UP for the principal, so
    # no separate flag is introduced that could drift from the incident.
    return True, {"enforced_by": "zerotrust.high_risk_incident"}


def _contain_subject(conn, context):
    if not context.affected_user_ids:
        return False, {"contained_user_ids": []}
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET contained = true WHERE id = ANY(%s) AND NOT contained RETURNING id",
            (list(context.affected_user_ids),),
        )
        changed = [row["id"] for row in cur.fetchall()]
    return bool(changed), {"contained_user_ids": changed, "in_scope": list(context.affected_user_ids)}


def _block_source(conn, context):
    if not context.source_ips:
        return False, {"blocked": []}
    blocked = []
    with conn.cursor() as cur:
        for source_ip in context.source_ips:
            cur.execute(
                """
                INSERT INTO blocked_sources (source_ip, incident_id, reason)
                VALUES (%(ip)s::inet, %(incident_id)s, %(reason)s)
                ON CONFLICT (source_ip) DO NOTHING
                RETURNING source_ip
                """,
                {
                    "ip": source_ip,
                    "incident_id": context.incident_id,
                    "reason": f"incident {context.incident_id} ({context.incident_classification})",
                },
            )
            if cur.fetchone() is not None:
                blocked.append(source_ip)
    return bool(blocked), {"blocked": blocked, "in_scope": list(context.source_ips)}


def _isolate_device(conn, context):
    if not context.device_ids:
        return False, {"isolated_device_ids": []}
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE devices SET isolated = true WHERE id = ANY(%s) AND NOT isolated RETURNING id",
            (list(context.device_ids),),
        )
        isolated = [row["id"] for row in cur.fetchall()]
    return bool(isolated), {"isolated_device_ids": isolated, "in_scope": list(context.device_ids)}


EXECUTORS = {
    config.ACTION_ALERT: _alert,
    config.ACTION_REQUIRE_STEP_UP: _require_step_up,
    config.ACTION_CONTAIN_SUBJECT: _contain_subject,
    config.ACTION_BLOCK_SOURCE: _block_source,
    config.ACTION_ISOLATE_DEVICE: _isolate_device,
}


# --- execution ---------------------------------------------------------------

# (incident_id, action) is unique, so this either inserts or returns the row
# already there. xmax = 0 distinguishes the two without a second query, making
# the claim atomic rather than a check-then-insert two concurrent workers could
# both pass.
CLAIM_SQL = """
    INSERT INTO responses (incident_id, threat_id, action, result, policy, reason, evidence, actor)
    VALUES (%(incident_id)s, %(threat_id)s, %(action)s, 'pending', %(policy)s, %(reason)s, %(evidence)s, %(actor)s)
    ON CONFLICT (incident_id, action) DO UPDATE SET result = responses.result
    RETURNING id, result, (xmax = 0) AS newly_claimed
"""

FINALISE_SQL = """
    UPDATE responses
    SET result = %(result)s, evidence = %(evidence)s, occurred_at = now()
    WHERE id = %(id)s
"""


def execute_response(conn, context: ResponseContext, plan: ResponsePlan, actor: str, threat_id=None) -> list:
    """Apply each action independently, recording its own result.

    Serialised per incident by an advisory lock, and backed by the unique
    constraint so a forgotten lock still cannot duplicate an action.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"response:incident:{context.incident_id}",))

    outcomes = []
    for action in plan.actions:
        with conn.cursor() as cur:
            cur.execute(
                CLAIM_SQL,
                {
                    "incident_id": context.incident_id,
                    "threat_id": threat_id,
                    "action": action,
                    "policy": plan.policy,
                    "reason": plan.reason,
                    "evidence": Jsonb({"plan": plan.to_dict()}),
                    "actor": actor,
                },
            )
            claim = cur.fetchone()

        already_done = not claim["newly_claimed"] and claim["result"] != config.RESULT_FAILED
        if already_done:
            # The action stands from an earlier evaluation. Nothing is
            # re-executed and the historical row is left exactly as it was.
            outcomes.append({"action": action, "result": config.RESULT_ALREADY_APPLIED, "detail": {}})
            continue

        try:
            applied, detail = EXECUTORS[action](conn, context)
            result = config.RESULT_EXECUTED if applied else config.RESULT_ALREADY_APPLIED
        except Exception as exc:
            log.exception(
                "response action failed",
                extra={"action": action, "incident_id": context.incident_id},
            )
            result, detail = config.RESULT_FAILED, {"error": type(exc).__name__}

        with conn.cursor() as cur:
            cur.execute(
                FINALISE_SQL,
                {
                    "id": claim["id"],
                    "result": result,
                    "evidence": Jsonb({"plan": plan.to_dict(), "detail": detail}),
                },
            )

        outcomes.append({"action": action, "result": result, "detail": detail})

    if outcomes:
        log.info(
            "response executed",
            extra={
                "incident_id": context.incident_id,
                "policy": plan.policy,
                "actions": [o["action"] for o in outcomes],
                "actor": actor,
            },
        )
    return outcomes


def respond_to_incident(conn, incident_id: int, actor: str, threat_id=None) -> dict | None:
    """Load context, decide, execute. The engine owns the action list."""
    context = load_response_context(conn, incident_id)
    if context is None:
        return None

    plan = evaluate_response(context)
    outcomes = execute_response(conn, context, plan, actor, threat_id)

    # The incident's status is deliberately not advanced to 'contained' here.
    # Phase 5 treats only open/investigating incidents as active, so closing the
    # loop automatically would make the incident stop denying access -- a
    # fail-open. Triage stays with the analyst.
    return {
        "incident_id": incident_id,
        "policy": plan.policy,
        "reason": plan.reason,
        "severity": plan.severity,
        "risk": plan.risk,
        "planned_actions": list(plan.actions),
        "actions": outcomes,
        "failed": [o["action"] for o in outcomes if o["result"] == config.RESULT_FAILED],
    }
