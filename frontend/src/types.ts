/** Mirrors the SentinelMesh REST API. Every security value here is produced by
 *  the backend; the dashboard never computes risk, policy or containment. */

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Decision = "allow" | "step_up" | "deny";
export type ResponseResult = "pending" | "succeeded" | "failed" | "skipped" | "already_applied";

export interface RiskFactor {
  factor: string;
  value: unknown;
  contribution: number;
  detail: string;
}

export interface RiskBreakdown {
  model_version: string;
  score: number;
  level: Severity;
  factors: RiskFactor[];
}

export interface Threat {
  id: number;
  event_id: number;
  threat_type: string;
  severity: Severity;
  confidence: number;
  rule_id: string;
  evidence: Record<string, unknown> & { reason?: string };
  detected_at: string;
  incident_id: number | null;
  risk_score: number | null;
  risk_level: Severity | null;
  risk_factors: Partial<RiskBreakdown>;
  risk_calculated_at: string | null;
}

export interface IncidentSummary {
  id: number;
  reference: string;
  title: string;
  classification: string;
  status: string;
  severity: Severity;
  risk_score: number;
  risk_factors: Partial<RiskBreakdown>;
  correlation_key: string;
  correlation_confidence: number | null;
  correlation_factors: {
    model_version?: string;
    explanation?: string;
    attack_stages?: string[];
    signals?: RiskFactor[];
    window_seconds?: number;
  };
  correlating: boolean;
  threat_count: number;
  created_at: string;
  last_activity_at: string;
}

export interface TimelineEntry {
  at: string;
  kind: "event" | "detection";
  detail: string;
  event_id?: number;
  threat_id?: number;
}

export interface IncidentThreat {
  id: number;
  threat_type: string;
  severity: Severity;
  confidence: number;
  rule_id: string;
  risk_score: number | null;
  risk_level: Severity | null;
  risk_factors: Partial<RiskBreakdown>;
  detected_at: string;
  reason: string | null;
  event: {
    id: number;
    event_type: string;
    source_ip: string | null;
    user_id: number | null;
    occurred_at: string;
  };
}

export interface ResponseAction {
  id: number;
  incident_id: number;
  threat_id: number | null;
  action: string;
  result: ResponseResult;
  policy: string | null;
  reason: string | null;
  evidence: Record<string, unknown>;
  actor: string | null;
  occurred_at: string;
}

export interface ZeroTrustRecord {
  id: number;
  decided_at: string;
  subject: string | null;
  subject_role: string | null;
  device_state: string;
  resource: string;
  sensitivity: string;
  decision: Decision;
  policy: string;
  reason: string;
  factors: RiskFactor[];
}

export interface Containment {
  subjects: { id: number; username: string; role: string; contained: boolean }[];
  sources: { source_ip: string; blocked: boolean }[];
  devices: { id: number; fingerprint: string; isolated: boolean; trust_score: number }[];
}

export interface IncidentDetail extends IncidentSummary {
  threats: IncidentThreat[];
  timeline: TimelineEntry[];
  responses: ResponseAction[];
  zero_trust: ZeroTrustRecord[];
  containment: Containment;
}

export interface SocSummary {
  incidents: { active: number; critical: number; high: number; other: number; total: number };
  containment: { contained_subjects: number; isolated_devices: number; blocked_sources: number };
  recent_threats: Threat[];
  recent_responses: ResponseAction[];
  recent_decisions: {
    id: number;
    decided_at: string;
    subject: string | null;
    resource: string;
    sensitivity: string;
    decision: Decision;
    policy: string;
    reason: string;
  }[];
}

export interface Page<T> {
  data: T[];
  next_cursor: string | null;
}

export interface SessionState {
  authenticated: boolean;
  operator?: string;
  scopes?: string[];
}
