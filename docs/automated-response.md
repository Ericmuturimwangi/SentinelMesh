# Automated Response Engine

Closes the SentinelMesh loop. Zero trust (Phase 5) answers *should this access be
allowed?*; this engine answers *what should SentinelMesh do about the security
state?* They are separate decisions — a critical incident makes Phase 5 deny an
access request **and** makes this engine contain the campaign.

## Containment is internal

**Every action changes SentinelMesh's own authoritative state.** Nothing here
touches a firewall, router, operating system, process, or any external system.
Containment is meaningful because the zero-trust engine enforces that state on
every subsequent access decision — not because it reaches outside the platform.

## Architecture

```
        load_response_context()      authoritative records only
                  |
           ResponseContext
                  |
          evaluate_response()        pure, no I/O, deterministic
                  |
            ResponsePlan
                  |
          execute_response()         per-action, independently audited
                  |
     responses rows + containment state
                  |
          Phase 5 enforcement        on every later access decision
```

Triggered automatically after correlation, in the same transaction as the threat
and incident it answers to. Because every action is internal database state, that
is atomic: there is no window where a response claims containment for a threat
that then rolls back. A manual re-evaluation endpoint exists for the SOC.

## Supported actions

| Action | Effect inside SentinelMesh |
|--------|----------------------------|
| `alert` | The audit row itself — what the SOC reads. |
| `require_step_up` | Records the directive. Enforced by Phase 5's `high_risk_incident` rule, so no duplicate flag can drift from the incident. |
| `contain_subject` | `users.contained = true`. Phase 5 then denies every request for that principal. |
| `block_source` | Row in `blocked_sources`. Phase 5 denies requests observed from that address. |
| `isolate_device` | `devices.isolated = true`. Phase 5 denies requests from that device. |

There is no `revoke_session`: SentinelMesh has no sessions (see Limitations).

## Policy and precedence

First match wins. An incident outranks a lone threat at the same tier — three
correlated threats forming a campaign warrant more than one isolated detection.

| # | Condition | Policy | Actions |
|---|-----------|--------|---------|
| 1 | incident risk ≥ 80 | `critical_incident_containment` | alert, contain_subject, block_source, isolate_device |
| 2 | threat risk ≥ 80 | `critical_threat_containment` | alert, contain_subject, block_source |
| 3 | incident risk ≥ 60 | `high_incident_escalation` | alert, require_step_up |
| 4 | threat risk ≥ 60 | `high_threat_escalation` | alert, require_step_up |
| 5 | risk ≥ 30 | `medium_monitoring` | alert |
| 6 | otherwise | `low_no_containment` | *(none)* |

LOW produces **no** actions — no containment and no alert noise for benign
activity. MEDIUM's "enhanced logging" is the audit record itself; no separate
logging pipeline was invented for a tier that needs no containment. A lone
critical threat contains the principal and address but does **not** isolate a
device: it is not yet a campaign.

Actions are filtered to entities legitimately part of the incident. A device is
in scope only if it belongs to the event's own principal *and* was named by that
event, so isolation cannot reach a device that took no part.

## Idempotency

`UNIQUE (incident_id, action)` on `responses` **is** the idempotency key: one
logical action per action type per incident, enforced by PostgreSQL rather than
by an `exists()` check two workers could both pass. The claim is a single
`INSERT ... ON CONFLICT DO UPDATE ... RETURNING (xmax = 0)`, so insert and
already-present are distinguished atomically.

- Action already applied → reported `already_applied`, **not re-executed**, and
  the historical row is left exactly as written.
- Action previously `failed` → retried on the next evaluation.

## Concurrency

`pg_advisory_xact_lock` on the incident serialises plan execution per campaign
(different incidents proceed in parallel), and the unique constraint is the
durable backstop if a future code path forgets the lock. Verified with four
synchronised workers producing exactly one row per action type.

## Audit model

Every executed action is one row in `responses`: incident, triggering threat,
action, result, policy, reason, evidence, actor, timestamp. Results use the
existing `response_result` vocabulary — `succeeded` (ran now), `already_applied`
(state was already in effect), `failed`. Records are never rewritten, so a
historical response does not change when the threat picture later does, and
carry no credentials or tokens.

## Failure behaviour

Each action is applied and recorded **independently**. One failure never reports
the others as successful: the plan returns a per-action result list and a
`failed` list.

The incident's status is deliberately **not** advanced to `contained`. Phase 5
treats only `open`/`investigating` incidents as active, so auto-closing the loop
would make the incident stop denying access — a fail-open. Triage stays with the
analyst.

A response fault runs in its own savepoint and cannot discard the detection that
triggered it: losing telemetry is worse than missing one containment, and the
incident stays visible to the SOC.

## Security limitations

- **No sessions exist to revoke.** Authentication is static API keys for
  services; the users being contained never authenticate to SentinelMesh at all.
  `contain_subject` is named honestly and is genuinely enforced at the Phase 5
  decision point, which is the enforcement point for user access here. Real
  session revocation would require a token store, issuance and expiry — a second
  authentication system.
- **Containment has no expiry.** A contained principal, blocked address or
  isolated device stays that way until an operator clears it; no unblock API
  exists yet.
- **No client can choose an action.** There is no endpoint that takes a user,
  device or address to contain — only an incident id, and the engine derives
  everything else.
- **`block_source` is address-based**, so it is evaded by rotating source
  addresses, and could contain a shared egress address used by others.
