import type { ReactNode } from "react";
import type { ResponseResult, Severity } from "../types";

/* Severity is never communicated by colour alone: every badge carries its label
   in text and a distinct glyph, so it survives greyscale and colour blindness. */

const SEVERITY_STYLE: Record<string, { cls: string; glyph: string }> = {
  critical: { cls: "text-critical bg-critical-quiet border-critical/40", glyph: "▲" },
  high: { cls: "text-high bg-high-quiet border-high/40", glyph: "◆" },
  medium: { cls: "text-medium bg-medium-quiet border-medium/40", glyph: "■" },
  low: { cls: "text-low bg-low-quiet border-low/40", glyph: "●" },
  info: { cls: "text-muted bg-sunken border-line", glyph: "·" },
};

export function RiskBadge({ level, score }: { level: Severity | null; score: number | null }) {
  const key = level ?? "info";
  const style = SEVERITY_STYLE[key] ?? SEVERITY_STYLE.info;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 font-mono text-[11px] font-semibold tracking-wide ${style.cls}`}
    >
      <span aria-hidden="true">{style.glyph}</span>
      <span className="uppercase">{key}</span>
      {score !== null && (
        <>
          <span aria-hidden="true" className="opacity-50">
            ·
          </span>
          <span>{score}</span>
        </>
      )}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const active = status === "open" || status === "investigating";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 font-mono text-[11px] uppercase tracking-wide ${
        active ? "border-accent/40 bg-accent-quiet text-accent" : "border-line bg-sunken text-muted"
      }`}
    >
      <span aria-hidden="true">{active ? "◇" : "✓"}</span>
      {status.replace(/_/g, " ")}
    </span>
  );
}

const RESULT_STYLE: Record<ResponseResult, { cls: string; glyph: string; label: string }> = {
  succeeded: { cls: "text-ok bg-ok-quiet border-ok/40", glyph: "✓", label: "succeeded" },
  already_applied: { cls: "text-muted bg-sunken border-line", glyph: "=", label: "already applied" },
  failed: { cls: "text-critical bg-critical-quiet border-critical/40", glyph: "✕", label: "failed" },
  pending: { cls: "text-medium bg-medium-quiet border-medium/40", glyph: "…", label: "pending" },
  skipped: { cls: "text-muted bg-sunken border-line", glyph: "–", label: "skipped" },
};

export function ResultBadge({ result }: { result: ResponseResult }) {
  const style = RESULT_STYLE[result] ?? RESULT_STYLE.pending;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 font-mono text-[11px] uppercase tracking-wide ${style.cls}`}
    >
      <span aria-hidden="true">{style.glyph}</span>
      {style.label}
    </span>
  );
}

const DECISION_STYLE: Record<string, { cls: string; glyph: string }> = {
  deny: { cls: "text-critical bg-critical-quiet border-critical/40", glyph: "✕" },
  step_up: { cls: "text-high bg-high-quiet border-high/40", glyph: "!" },
  allow: { cls: "text-ok bg-ok-quiet border-ok/40", glyph: "✓" },
};

export function DecisionBadge({ decision, large }: { decision: string; large?: boolean }) {
  const style = DECISION_STYLE[decision] ?? DECISION_STYLE.step_up;
  return (
    <span
      className={`inline-flex items-center gap-2 rounded border font-mono font-semibold uppercase tracking-wide ${style.cls} ${
        large ? "px-3 py-1.5 text-base" : "px-1.5 py-0.5 text-[11px]"
      }`}
    >
      <span aria-hidden="true">{style.glyph}</span>
      {decision.replace(/_/g, " ")}
    </span>
  );
}

export function Panel({
  title,
  aside,
  children,
  className = "",
}: {
  title: string;
  aside?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-md border border-line bg-raised ${className}`}>
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-3 py-2">
        <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-muted">{title}</h2>
        {aside}
      </header>
      <div className="p-3">{children}</div>
    </section>
  );
}

export function MetricCard({
  label,
  value,
  tone = "neutral",
  hint,
}: {
  label: string;
  value: number | string;
  tone?: "neutral" | "critical" | "high" | "ok";
  hint?: string;
}) {
  const tones = {
    neutral: "text-ink",
    critical: "text-critical",
    high: "text-high",
    ok: "text-ok",
  } as const;
  return (
    <div className="rounded-md border border-line bg-raised px-3 py-2.5">
      <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.09em] text-faint">{label}</div>
      <div className={`mt-1 font-mono text-2xl leading-none font-semibold tabular-nums ${tones[tone]}`}>{value}</div>
      {hint && <div className="mt-1 text-[11px] text-faint">{hint}</div>}
    </div>
  );
}

export function Skeleton({ rows = 3, className = "" }: { rows?: number; className?: string }) {
  return (
    <div className={`space-y-2 ${className}`} role="status" aria-label="Loading">
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="skeleton h-8" style={{ opacity: 1 - index * 0.12 }} />
      ))}
      <span className="sr-only">Loading…</span>
    </div>
  );
}

export function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded border border-dashed border-line px-4 py-8 text-center">
      <p className="text-sm font-medium text-ink">{title}</p>
      <p className="mx-auto mt-1 max-w-md text-[13px] text-muted">{body}</p>
    </div>
  );
}

export function ErrorState({ title, body, onRetry }: { title: string; body: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="rounded border border-critical/40 bg-critical-quiet px-4 py-6 text-center">
      <p className="text-sm font-semibold text-critical">{title}</p>
      <p className="mx-auto mt-1 max-w-md text-[13px] text-muted">{body}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-3 rounded border border-line-strong bg-raised px-3 py-1.5 text-[13px] font-medium text-ink hover:bg-sunken"
        >
          Retry
        </button>
      )}
    </div>
  );
}

export function clock(iso: string) {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function stamp(iso: string) {
  return new Date(iso).toLocaleString([], {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function humanise(value: string) {
  return value.replace(/[._]/g, " ");
}
