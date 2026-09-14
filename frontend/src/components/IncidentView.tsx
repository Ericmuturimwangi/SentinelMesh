import { useState } from "react";
import type { IncidentDetail } from "../types";
import {
  AttackChain,
  ContainmentPanel,
  CorrelationPanel,
  ResponsePanel,
  RiskFactors,
  ThreatDetail,
  Timeline,
  ZeroTrustPanel,
} from "./panels";
import { Panel, RiskBadge, StatusBadge, humanise, stamp } from "./primitives";

export function IncidentView({ incident, onBack }: { incident: IncidentDetail; onBack: () => void }) {
  const [selectedThreat, setSelectedThreat] = useState<number | null>(null);
  const threat = incident.threats.find((t) => t.id === selectedThreat) ?? null;

  return (
    <div className="space-y-4">
      <button
        type="button"
        onClick={onBack}
        className="inline-flex items-center gap-1.5 rounded px-1 py-0.5 font-mono text-[11px] uppercase tracking-wide text-muted hover:text-ink"
      >
        <span aria-hidden="true">←</span> Incidents
      </button>

      <header className="rounded-md border border-line bg-raised px-4 py-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="font-mono text-xl font-semibold tracking-tight text-ink">{incident.reference}</h1>
            <p className="mt-0.5 text-[15px] font-medium text-ink">{humanise(incident.classification).toUpperCase()}</p>
            <p className="mt-1 font-mono text-[11px] text-faint">
              {incident.correlation_key} · {incident.threat_count} threat
              {incident.threat_count === 1 ? "" : "s"} · last activity {stamp(incident.last_activity_at)}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <RiskBadge level={incident.severity} score={incident.risk_score} />
            <StatusBadge status={incident.status} />
            {!incident.correlating && (
              <span className="rounded border border-line bg-sunken px-1.5 py-0.5 font-mono text-[11px] uppercase text-muted">
                no longer accumulating
              </span>
            )}
          </div>
        </div>
      </header>

      <Panel title="Attack chain">
        <AttackChain stages={incident.correlation_factors.attack_stages ?? []} />
      </Panel>

      <div className="grid items-start gap-4 lg:grid-cols-2">
        <Panel title="Incident risk">
          <RiskFactors breakdown={incident.risk_factors} label="Incident risk" />
        </Panel>
        <Panel title="Correlation">
          <CorrelationPanel incident={incident} />
        </Panel>
      </div>

      <Panel title="Timeline" aside={<span className="text-[11px] text-faint">Select a detection for evidence</span>}>
        <Timeline entries={incident.timeline} threats={incident.threats} onSelectThreat={setSelectedThreat} />
      </Panel>

      {threat && (
        <>
          <ThreatDetail threat={threat} incident={incident} onClose={() => setSelectedThreat(null)} />
          <Panel title={`Threat risk · ${threat.threat_type}`}>
            <RiskFactors breakdown={threat.risk_factors} label="Threat risk" />
          </Panel>
        </>
      )}

      <div className="grid items-start gap-4 lg:grid-cols-2">
        <Panel title="Zero trust">
          <ZeroTrustPanel records={incident.zero_trust} />
        </Panel>
        <Panel title="Current containment">
          <ContainmentPanel containment={incident.containment} />
        </Panel>
      </div>

      <Panel title="Automated response">
        <ResponsePanel actions={incident.responses} />
      </Panel>
    </div>
  );
}
