import type { IncidentSummary, SocSummary } from "../types";
import { EmptyState, MetricCard, Panel, ResultBadge, RiskBadge, StatusBadge, clock, humanise, stamp } from "./primitives";

const STATUS_FILTERS = [
  { value: "", label: "All" },
  { value: "open", label: "Open" },
  { value: "investigating", label: "Investigating" },
  { value: "contained", label: "Contained" },
  { value: "resolved", label: "Resolved" },
] as const;

export function Overview({
  summary,
  incidents,
  status,
  onStatusChange,
  onSelect,
  onLoadMore,
  hasMore,
}: {
  summary: SocSummary;
  incidents: IncidentSummary[];
  status: string;
  onStatusChange: (status: string) => void;
  onSelect: (id: number) => void;
  onLoadMore: () => void;
  hasMore: boolean;
}) {
  const { incidents: counts, containment } = summary;
  const containedTotal =
    containment.contained_subjects + containment.isolated_devices + containment.blocked_sources;

  return (
    <div className="space-y-4">
      <section aria-label="Security posture">
        <h2 className="sr-only">Security posture</h2>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <MetricCard label="Critical" value={counts.critical} tone={counts.critical > 0 ? "critical" : "neutral"} />
          <MetricCard label="High" value={counts.high} tone={counts.high > 0 ? "high" : "neutral"} />
          <MetricCard label="Active incidents" value={counts.active} />
          <MetricCard label="Containment" value={containedTotal} tone={containedTotal > 0 ? "ok" : "neutral"} hint="subjects · devices · sources" />
          <MetricCard label="Total incidents" value={counts.total} />
        </div>
      </section>

      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Panel
          title="Incidents"
          aside={
            <label className="flex items-center gap-2 text-[11px] text-muted">
              <span className="font-mono uppercase tracking-wide">Status</span>
              <select
                value={status}
                onChange={(event) => onStatusChange(event.target.value)}
                className="rounded border border-line bg-surface px-2 py-1 text-[12px] text-ink"
                aria-label="Filter incidents by status"
              >
                {STATUS_FILTERS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
          }
        >
          {incidents.length === 0 ? (
            <EmptyState
              title="No incidents"
              body="SentinelMesh has not correlated any threats into an incident for the selected status."
            />
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[34rem] border-collapse text-left text-[13px]">
                  <caption className="sr-only">Correlated security incidents</caption>
                  <thead>
                    <tr className="border-b border-line font-mono text-[10px] uppercase tracking-wide text-faint">
                      <th scope="col" className="py-1.5 pr-3 font-normal">Ref</th>
                      <th scope="col" className="py-1.5 pr-3 font-normal">Classification</th>
                      <th scope="col" className="py-1.5 pr-3 font-normal">Risk</th>
                      <th scope="col" className="py-1.5 pr-3 font-normal">Status</th>
                      <th scope="col" className="py-1.5 pr-3 text-right font-normal">Threats</th>
                      <th scope="col" className="py-1.5 pr-3 text-right font-normal">Corr.</th>
                      <th scope="col" className="py-1.5 text-right font-normal">Last activity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {incidents.map((incident) => (
                      <tr
                        key={incident.id}
                        tabIndex={0}
                        role="button"
                        aria-label={`Open incident ${incident.reference}`}
                        onClick={() => onSelect(incident.id)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            onSelect(incident.id);
                          }
                        }}
                        className="cursor-pointer border-b border-line/60 last:border-b-0 hover:bg-sunken"
                      >
                        <td className="py-2 pr-3 font-mono font-medium text-ink">{incident.reference}</td>
                        <td className="py-2 pr-3 text-muted">{humanise(incident.classification)}</td>
                        <td className="py-2 pr-3">
                          <RiskBadge level={incident.severity} score={incident.risk_score} />
                        </td>
                        <td className="py-2 pr-3">
                          <StatusBadge status={incident.status} />
                        </td>
                        <td className="py-2 pr-3 text-right font-mono tabular-nums text-muted">
                          {incident.threat_count}
                        </td>
                        <td className="py-2 pr-3 text-right font-mono tabular-nums text-muted">
                          {incident.correlation_confidence === null
                            ? "—"
                            : incident.correlation_confidence.toFixed(2)}
                        </td>
                        <td className="py-2 text-right font-mono text-[11px] tabular-nums text-faint">
                          {stamp(incident.last_activity_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {hasMore && (
                <button
                  type="button"
                  onClick={onLoadMore}
                  className="mt-3 w-full rounded border border-line px-3 py-1.5 text-[13px] text-muted hover:bg-sunken"
                >
                  Load more incidents
                </button>
              )}
            </>
          )}
        </Panel>

        <div className="space-y-4">
          <Panel title="Threat activity">
            {summary.recent_threats.length === 0 ? (
              <EmptyState title="No threats detected" body="No detection rule has fired yet." />
            ) : (
              <ul className="space-y-1">
                {summary.recent_threats.map((threat) => (
                  <li key={threat.id} className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <time className="font-mono text-[11px] tabular-nums text-faint">{clock(threat.detected_at)}</time>
                    <span className="font-mono text-[13px] text-ink">{threat.threat_type}</span>
                    <span className="ml-auto">
                      <RiskBadge level={threat.risk_level} score={threat.risk_score} />
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel title="Recent response actions">
            {summary.recent_responses.length === 0 ? (
              <EmptyState title="No automated responses" body="No incident has met the threshold for containment." />
            ) : (
              <ul className="space-y-1">
                {summary.recent_responses.map((action) => (
                  <li key={action.id} className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <time className="font-mono text-[11px] tabular-nums text-faint">{clock(action.occurred_at)}</time>
                    <span className="font-mono text-[13px] text-ink uppercase">{humanise(action.action)}</span>
                    <span className="font-mono text-[11px] text-faint">SM-{String(action.incident_id).padStart(3, "0")}</span>
                    <span className="ml-auto">
                      <ResultBadge result={action.result} />
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel title="Containment state">
            <dl className="grid grid-cols-3 gap-3 text-center">
              {[
                ["Subjects", containment.contained_subjects, "contained"],
                ["Devices", containment.isolated_devices, "isolated"],
                ["Sources", containment.blocked_sources, "blocked"],
              ].map(([label, value, verb]) => (
                <div key={label as string} className="rounded border border-line bg-sunken px-2 py-2">
                  <dt className="font-mono text-[10px] uppercase tracking-wide text-faint">{label}</dt>
                  <dd
                    className={`mt-1 font-mono text-xl leading-none font-semibold tabular-nums ${
                      (value as number) > 0 ? "text-critical" : "text-faint"
                    }`}
                  >
                    {value as number}
                  </dd>
                  <dd className="mt-0.5 text-[10px] text-faint">{verb as string}</dd>
                </div>
              ))}
            </dl>
          </Panel>
        </div>
      </div>
    </div>
  );
}
