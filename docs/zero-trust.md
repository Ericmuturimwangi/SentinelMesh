# Zero-Trust Decision Engine

Authentication alone does not imply authorization. A legitimate authenticated
user is still denied or challenged when their device, threat history, incident
state or requested resource makes the access unsafe.

## Architecture

```
Incident / Threat / Device / Identity / Resource
                      |
              load_access_context()      reads authoritative records
                      |
                 AccessContext
                      |
               evaluate_access()         pure, no I/O, deterministic
                      |
                AccessDecision
                      |
              record_decision()          immutable audit row
                      |
            ALLOW / STEP_UP / DENY
```

`evaluate_access` performs no database access, so the policy is testable in
isolation. The engine **consumes** Phase 3 threat risk and Phase 4 incidents; it
never recomputes either.

## Decision outcomes

| Outcome   | Meaning |
|-----------|---------|
| `allow`   | Access proceeds. |
| `step_up` | Access is possible but requires further verification. Not a failure. |
| `deny`    | Access refused under current security context. |

## Policy precedence

Rules are evaluated in this exact order and **the first match decides**. Every
DENY rule precedes every STEP_UP rule, so a condition that forbids access can
never be softened by a later rule that would merely challenge it.

| # | Policy | Outcome |
|---|--------|---------|
| 1 | `identity_unauthenticated` | DENY |
| 2 | `identity_unknown` | DENY |
| 3 | `critical_incident` | DENY |
| 4 | `critical_threat` | DENY |
| 5 | `insufficient_privilege` | DENY |
| 6 | `high_risk_sensitive_resource` | DENY |
| 7 | `untrusted_device_sensitive_resource` | DENY |
| 8 | `high_risk_incident` | STEP_UP |
| 9 | `high_risk_threat` | STEP_UP |
| 10 | `device_not_trusted` | STEP_UP |
| 11 | `elevated_risk` | STEP_UP |
| 12 | `privileged_resource` | STEP_UP |
| 13 | `trusted_baseline` | ALLOW |

Risk thresholds are the Phase 3 band floors (`medium` 30, `high` 60,
`critical` 80), reused rather than restated so retuning a band cannot leave the
authorization thresholds behind.

## Resource sensitivity

`public` < `internal` < `sensitive` < `critical`, derived from the resource path
by server policy. An unrecognised path is treated as `sensitive`: where
uncertainty affects authorization, fail closed.

## Explainability

Every decision carries a `policy`, a one-sentence `reason`, and factors across
five categories — identity, device, threat, incident, resource. There is
deliberately **no decision confidence score**: authorization is a policy
outcome, not a probability. Threat confidence (Phase 3) and correlation
confidence (Phase 4) remain separate concepts and are never folded into the
verdict.

## Security assumptions

- The endpoint is a **Policy Decision Point**. A caller holding the `decide`
  scope is a Policy Enforcement Point trusted to *name* the subject it has
  already authenticated. That is the one assertion it may make.
- Everything else is read from authoritative records: role from `users`, device
  trust from `devices` (scoped to the subject's own user, so a fingerprint
  belonging to someone else does not resolve), risk from `threats`, campaign
  state from `incidents`, sensitivity from server config.
- Role, risk, severity, device trust, incident state, sensitivity, decision and
  policy are all **rejected** if a client submits them.
- Decisions are committed before the verdict is returned, so a failed audit
  write surfaces as an error rather than an unaudited ALLOW.
- Audit rows are append-only; nothing in the application updates them, so a
  historical verdict does not change when the threat picture later does.

## Known limitations

- A `decide` credential that lies about `subject_user_id` evaluates access as
  another user. Binding credentials to identities would remove this, at the cost
  of one credential per end user. The asking credential is recorded on every
  decision.
- `source_ip` is supplied by the enforcement point; omitting it narrows the
  threat context to identity alone.
- Incidents gate on status, so access stays denied until an analyst triages the
  incident. This is intentional, but there is no automatic expiry.
- There is no inactive/disabled user concept in `users`; only absence of the
  record denies on identity grounds.
- `step_up` is returned as a verdict; no challenge mechanism is implemented.
