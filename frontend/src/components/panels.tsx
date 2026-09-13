import type { Containment, IncidentDetail, ResponseAction, RiskBreakdown, TimelineEntry, ZeroTrustRecord } from "../types";
import { DecisionBadge, EmptyState, Panel, ResultBadge, RiskBadge, clock, humanise, stamp } from "./primitives";

/* Every number in these panels is read from the API. The dashboard renders the
   backend's risk, correlation, policy and containment verdicts -- it never
   recomputes them, and never sums the factors itself. */

export function RiskFactors({ breakdown, label }: { breakdown: Partial<RiskBreakdown>; label: string }) {
  const factors = breakdown.factors ?? [];
  if (!factors.length) {
    return <EmptyState title="No risk breakdown" body="The backend has not scored this record yet." />;
  }
  return (
    <div>
      <div className="mb-3 flex items-baseline gap-2">
        <span className="font-mono text-3xl leading-none font-semibold tabular-nums text-ink">
          {breakdown.score ?? "—"}
        </span>
        <span className="text-[13px] text-faint">/ 100</span>
        <RiskBadge level={breakdown.level ?? null} score={null} />
      </div>
      <table className="w-full border-collapse text-[13px]">
        <caption className="sr-only">{label} factors, as calculated by the backend</caption>
        <tbody>
          {factors.map((factor) => (
            <tr key={factor.factor} className="border-t border-line/60 align-top first:border-t-0">
              <th scope="row" className="py-1.5 pr-3 text-left font-normal text-muted">
                <span className="block">{humanise(factor.factor)}</span>
                <span className="block text-[11px] text-faint">{factor.detail}</span>
              </th>
              <td
                className={`w-14 py-1.5 text-right font-mono tabular-nums ${
                  factor.contribution > 0 ? "text-ink" : factor.contribution < 0 ? "text-critical" : "text-faint"
                }`}
              >
                {factor.contribution > 0 ? `+${factor.contribution}` : factor.contribution}
              </td>
            </tr>
          ))}
          <tr className="border-t-2 border-line-strong">
            <th scope="row" className="py-1.5 pr-3 text-left font-mono text-[11px] uppercase tracking-wide text-muted">
              Backend score
            </th>
            <td className="py-1.5 text-right font-mono font-semibold tabular-nums text-ink">
              {breakdown.score ?? "—"}
            </td>
          </tr>
        </tbody>
      </table>
      {breakdown.model_version && (
        <p className="mt-2 font-mono text-[10px] text-faint">model {breakdown.model_version}</p>
      )}
    </div>
  );
}

export function CorrelationPanel({ incident }: { incident: IncidentDetail }) {
  const confidence = incident.correlation_confidence;
  const strength = confidence === null ? "—" : confidence >= 0.75 ? "HIGH" : "MODERATE";
  const signals = incident.correlation_factors.signals ?? [];

  return (
    <div>
      <div className="mb-3 flex items-baseline gap-2">
        <span className="font-mono text-3xl leading-none font-semibold tabular-nums text-ink">
          {confidence === null ? "—" : confidence.toFixed(3)}
        </span>
        <span className="font-mono text-[11px] font-semibold uppercase tracking-wide text-muted">{strength}</span>
      </div>
      {incident.correlation_factors.explanation && (
        <p className="mb-3 text-[13px] leading-relaxed text-muted">{incident.correlation_factors.explanation}</p>
      )}
      {signals.length > 0 ? (
        <ul className="space-y-1.5">
          {signals.map((signal) => (
            <li key={signal.factor} className="flex items-start justify-between gap-3 text-[13px]">
              <span className="text-muted">
                <span className="block">{humanise(signal.factor)}</span>
                <span className="block text-[11px] text-faint">{signal.detail}</span>
              </span>
              <span
                className={`font-mono tabular-nums ${signal.contribution > 0 ? "text-ink" : "text-faint"}`}
              >
                {signal.contribution > 0 ? `+${signal.contribution}` : signal.contribution}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-[13px] text-faint">
          A single-threat incident has no correlation link to score yet.
        </p>
      )}
    </div>
  );
}

export function AttackChain({ stages }: { stages: string[] }) {
  if (!stages.length) {
    return (
      <EmptyState
        title="No attack progression"
        body="This incident has not advanced through multiple attack stages."
      />
    );
  }
  return (
    <ol className="flex flex-col gap-0 sm:flex-row sm:items-stretch sm:gap-0">
      {stages.map((stage, index) => (
        <li key={stage} className="flex items-center gap-2 sm:flex-1 sm:flex-col sm:items-stretch sm:gap-2">
          <div className="flex flex-1 items-center gap-2 rounded border border-line bg-sunken px-3 py-2 sm:flex-none">
            <span className="font-mono text-[11px] text-faint tabular-nums">{index + 1}</span>
            <span className="text-[13px] font-medium text-ink">{stage}</span>
          </div>
          {index < stages.length - 1 && (
            <>
              <span aria-hidden="true" className="px-1 text-faint sm:hidden">
                ↓
              </span>
              <span aria-hidden="true" className="hidden text-center text-faint sm:block">
                ↓
              </span>
            </>
          )}
        </li>
      ))}
    </ol>
  );
}

export function Timeline({
  entries,
  threats,
  onSelectThreat,
}: {
  entries: TimelineEntry[];
  threats: IncidentDetail["threats"];
  onSelectThreat: (id: number) => void;
}) {
  if (!entries.length) {
    return <EmptyState title="No timeline" body="No events or detections are recorded for this incident." />;
  }
  const byThreat = new Map(threats.map((t) => [t.id, t]));

  return (
    <ol className="relative space-y-1 border-l border-line pl-4">
      {entries.map((entry, index) => {
        const threat = entry.threat_id ? byThreat.get(entry.threat_id) : undefined;
        const isDetection = entry.kind === "detection";
        return (
          <li key={`${entry.at}-${entry.kind}-${index}`} className="relative">
            <span
              aria-hidden="true"
              className={`absolute top-2.5 -left-[21px] h-2 w-2 rounded-full border ${
                isDetection ? "border-critical bg-critical" : "border-line-strong bg-surface"
              }`}
            />
            {threat ? (
              <button
                type="button"
                onClick={() => onSelectThreat(threat.id)}
                className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 rounded px-2 py-1.5 text-left hover:bg-sunken"
                aria-label={`Inspect threat ${threat.threat_type}`}
              >
                <time className="font-mono text-[11px] tabular-nums text-faint">{clock(entry.at)}</time>
                <span className="font-mono text-[13px] text-ink">{threat.threat_type}</span>
                <RiskBadge level={threat.risk_level} score={threat.risk_score} />
                <span className="text-[11px] text-faint">{threat.rule_id}</span>
              </button>
            ) : (
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-2 py-1.5">
                <time className="font-mono text-[11px] tabular-nums text-faint">{clock(entry.at)}</time>
                <span className="text-[13px] text-muted">{entry.detail}</span>
              </div>
            )}
          </li>
        );
      })}
    </ol>
  );
}

export function ZeroTrustPanel({ records }: { records: ZeroTrustRecord[] }) {
  if (!records.length) {
    return (
      <EmptyState
        title="No access decisions"
        body="No access has been evaluated against this incident yet. Decisions appear here once a policy enforcement point asks."
      />
    );
  }
  const [latest, ...earlier] = records;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <DecisionBadge decision={latest.decision} large />
        <div className="font-mono text-[12px] text-muted">
          policy <span className="text-ink">{latest.policy}</span>
        </div>
        <time className="ml-auto font-mono text-[11px] text-faint">{stamp(latest.decided_at)}</time>
      </div>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-[13px] sm:grid-cols-3">
        {[
          ["Identity", `${latest.subject ?? "unauthenticated"}${latest.subject_role ? ` · ${latest.subject_role}` : ""}`],
          ["Device", latest.device_state],
          ["Resource", `${latest.resource} · ${latest.sensitivity}`],
        ].map(([term, value]) => (
          <div key={term}>
            <dt className="font-mono text-[10px] uppercase tracking-wide text-faint">{term}</dt>
            <dd className="mt-0.5 break-words text-ink">{value}</dd>
          </div>
        ))}
      </dl>

      <p className="rounded border border-line bg-sunken px-3 py-2 text-[13px] leading-relaxed text-muted">
        {latest.reason}
      </p>

      {earlier.length > 0 && (
        <details className="text-[13px]">
          <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-wide text-muted">
            {earlier.length} earlier decision{earlier.length > 1 ? "s" : ""}
          </summary>
          <ul className="mt-2 space-y-1">
            {earlier.map((record) => (
              <li key={record.id} className="flex flex-wrap items-center gap-2">
                <time className="font-mono text-[11px] tabular-nums text-faint">{clock(record.decided_at)}</time>
                <DecisionBadge decision={record.decision} />
                <span className="font-mono text-[12px] text-muted">{record.policy}</span>
                <span className="font-mono text-[11px] text-faint">{record.resource}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

export function ResponsePanel({ actions }: { actions: ResponseAction[] }) {
  if (!actions.length) {
    return (
      <EmptyState
        title="No automated response"
        body="This incident did not meet the threshold for an automated containment action."
      />
    );
  }
  return (
    <ol className="space-y-1">
      {actions.map((action, index) => (
        <li key={action.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded px-2 py-1.5 odd:bg-sunken/60">
          <span aria-hidden="true" className="font-mono text-[11px] text-faint tabular-nums">
            {index + 1}
          </span>
          <span className="font-mono text-[13px] font-medium tracking-wide text-ink uppercase">
            {humanise(action.action)}
          </span>
          <ResultBadge result={action.result} />
          {action.policy && <span className="font-mono text-[11px] text-faint">{action.policy}</span>}
          <time className="ml-auto font-mono text-[11px] tabular-nums text-faint">{clock(action.occurred_at)}</time>
          {action.reason && <p className="w-full pl-6 text-[12px] text-muted">{action.reason}</p>}
        </li>
      ))}
    </ol>
  );
}

export function ContainmentPanel({ containment }: { containment: Containment }) {
  const rows: { label: string; name: string; active: boolean; activeLabel: string; idleLabel: string }[] = [
    ...containment.subjects.map((s) => ({
      label: "Subject",
      name: `${s.username} · ${s.role}`,
      active: s.contained,
      activeLabel: "CONTAINED",
      idleLabel: "not contained",
    })),
    ...containment.devices.map((d) => ({
      label: "Device",
      name: d.fingerprint,
      active: d.isolated,
      activeLabel: "ISOLATED",
      idleLabel: "not isolated",
    })),
    ...containment.sources.map((s) => ({
      label: "Source",
      name: s.source_ip,
      active: s.blocked,
      activeLabel: "BLOCKED",
      idleLabel: "not blocked",
    })),
  ];

  if (!rows.length) {
    return <EmptyState title="Nothing in scope" body="This incident has no subject, device or source to contain." />;
  }

  return (
    <>
      <p className="mb-2 text-[12px] text-faint">
        Current state, not response history. Containment applies inside SentinelMesh.
      </p>
      <ul className="space-y-1">
        {rows.map((row, index) => (
          <li key={`${row.label}-${row.name}-${index}`} className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="w-16 font-mono text-[10px] uppercase tracking-wide text-faint">{row.label}</span>
            <span className="font-mono text-[13px] text-ink">{row.name}</span>
            <span
              className={`ml-auto inline-flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wide ${
                row.active ? "text-critical" : "text-faint"
              }`}
            >
              <span aria-hidden="true">{row.active ? "●" : "○"}</span>
              {row.active ? row.activeLabel : row.idleLabel}
            </span>
          </li>
        ))}
      </ul>
    </>
  );
}

export function ThreatDetail({
  threat,
  incident,
  onClose,
}: {
  threat: IncidentDetail["threats"][number];
  incident: IncidentDetail;
  onClose: () => void;
}) {
  const facts: [string, string][] = [
    ["Threat", `#${threat.id}`],
    ["Type", threat.threat_type],
    ["Severity", threat.severity],
    ["Confidence", threat.confidence.toFixed(3)],
    ["Risk", threat.risk_score === null ? "—" : `${threat.risk_score} ${threat.risk_level ?? ""}`],
    ["Rule", threat.rule_id],
    ["Event", `#${threat.event.id} ${threat.event.event_type}`],
    ["Source", threat.event.source_ip ?? "—"],
    ["Principal", threat.event.user_id === null ? "unauthenticated" : `user ${threat.event.user_id}`],
    ["Incident", incident.reference],
    ["Detected", stamp(threat.detected_at)],
  ];

  return (
    <Panel
      title={`Threat evidence · ${threat.threat_type}`}
      aside={
        <button
          type="button"
          onClick={onClose}
          className="rounded border border-line px-2 py-0.5 font-mono text-[11px] text-muted hover:bg-sunken"
        >
          Close
        </button>
      }
    >
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-[13px] sm:grid-cols-3 lg:grid-cols-4">
        {facts.map(([term, value]) => (
          <div key={term}>
            <dt className="font-mono text-[10px] uppercase tracking-wide text-faint">{term}</dt>
            {/* Rendered as text, never as markup: this is attacker-controlled. */}
            <dd className="mt-0.5 font-mono break-words text-ink">{value}</dd>
          </div>
        ))}
      </dl>
      {threat.reason && (
        <p className="mt-3 rounded border border-line bg-sunken px-3 py-2 text-[13px] leading-relaxed text-muted">
          {threat.reason}
        </p>
      )}
    </Panel>
  );
}
