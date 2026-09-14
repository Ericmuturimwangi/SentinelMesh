# SOC Dashboard

A thin security-operations client over the Phase 1–6 pipeline. The backend
remains the security authority: the dashboard renders risk, classification,
zero-trust verdicts and containment state, and **never computes any of them**.

## Architecture

```
React SPA  ──(same origin)──>  Flask  ──>  PostgreSQL
    |                            |
 renders                    serves the SPA,
 verdicts                   owns every verdict
```

Flask serves the built bundle from `frontend/dist` and the API from the same
origin, which is what allows a `SameSite=Strict` session cookie. The SPA
catch-all is registered last and refuses `/api/` and `/soc/` paths, so it can
never shadow an API route.

## Authentication

The browser never holds a service credential.

1. An operator signs in at `POST /soc/login` with an existing **read-scoped**
   SentinelMesh API key.
2. Flask validates it against `SENTINELMESH_API_KEYS` and stores only the key
   *name* in a signed, `HttpOnly`, `SameSite=Strict`, `Secure` cookie.
3. Every later request re-resolves that name from configuration, so a credential
   removed from the environment stops working immediately.

The session grants exactly the scopes the credential already had — it is a
browser transport for the existing scoped-credential design, not a second
authentication system. A `read` session cannot ingest events or trigger
containment. Nothing security-related is written to `localStorage`; only a theme
preference is stored there.

For local http development set `SENTINELMESH_INSECURE_COOKIES=1`. Set
`SENTINELMESH_SECRET_KEY` in production, otherwise an ephemeral key is generated
and sessions simply do not survive a restart.

## API endpoints used

| Endpoint | Purpose |
|---|---|
| `POST /soc/login`, `POST /soc/logout`, `GET /soc/session` | Dashboard session |
| `GET /api/soc/summary/` | Overview counts, containment totals, recent threats/responses/decisions |
| `GET /api/incidents/?sort=risk&status=&limit=&cursor=` | Incident queue, worst-first |
| `GET /api/incidents/<id>` | Whole investigation in one request |

`GET /api/incidents/<id>` deliberately returns the incident, its threats (each
with its Phase 3 risk factors), the derived timeline, zero-trust decisions,
response actions and current containment together, so the dashboard never makes
N+1 calls.

## Refresh strategy

Polling every 15 seconds — no WebSockets. The dashboard stays correct without a
streaming transport and the backend needs no new infrastructure. Only the view
in front of the operator is refreshed.

## Incident investigation workflow

1. **Overview** — critical/high counts, the incident queue ordered worst-first
   by the backend, recent threat activity, recent response actions, and current
   containment totals.
2. **Incident** — attack chain, incident risk factors, correlation signals and
   confidence, timeline, zero-trust decision, current containment, and the
   automated response escalation.
3. **Threat** — selecting a detection in the timeline reveals its evidence and
   its own Phase 3 risk breakdown.

Incident ordering uses a composite keyset cursor (`risk_score:id`) so paging a
risk-sorted queue never repeats or skips an incident.

## Design and accessibility

Dark is the default SOC presentation with a light mode toggle; the initial value
follows the operator's system preference. Severity is **never** conveyed by
colour alone — every badge carries its label as text plus a distinct glyph
(`▲ CRITICAL · 100`, `◆ HIGH · 64`), so it survives greyscale and colour
blindness. Tables use real `<table>` semantics with scoped headers, rows are
keyboard-operable, focus is always visible, and no information is hover-only.

Threat evidence is attacker-controlled and is rendered as text through JSX only.
There is no `dangerouslySetInnerHTML` anywhere in the dashboard.

## Known limitations

- Filtering covers status only; severity and time-range filters would need
  further backend query parameters.
- The risk-sorted queue has no supporting composite index; at larger volumes
  `(risk_score DESC, id DESC)` would be worth adding, measured first.
- Polling means up to 15 seconds of staleness.
- There is no incident triage action in the UI: the dashboard observes, and
  status changes remain a backend concern.
