import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api } from "./api";
import { IncidentView } from "./components/IncidentView";
import { Overview } from "./components/Overview";
import { SignIn } from "./components/SignIn";
import { ErrorState, Panel, Skeleton } from "./components/primitives";
import type { IncidentDetail, IncidentSummary, SessionState, SocSummary } from "./types";

const REFRESH_MS = 15_000;
const PAGE_SIZE = 20;

function incidentIdFromHash(): number | null {
  const match = window.location.hash.match(/^#\/incidents\/(\d+)$/);
  return match ? Number(match[1]) : null;
}

function useTheme() {
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    const stored = localStorage.getItem("sm-theme");
    if (stored === "light" || stored === "dark") return stored;
    return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
  });

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    // Only a display preference is persisted -- never anything security related.
    localStorage.setItem("sm-theme", theme);
  }, [theme]);

  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))] as const;
}

export default function App() {
  const [session, setSession] = useState<SessionState | null>(null);
  const [summary, setSummary] = useState<SocSummary | null>(null);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [status, setStatus] = useState("");
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [selected, setSelected] = useState<number | null>(incidentIdFromHash());
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [theme, toggleTheme] = useTheme();
  const loadedOnce = useRef(false);

  useEffect(() => {
    api
      .session()
      .then(setSession)
      .catch(() => setSession({ authenticated: false }));
  }, []);

  useEffect(() => {
    const onHashChange = () => setSelected(incidentIdFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const loadOverview = useCallback(async () => {
    try {
      const [nextSummary, page] = await Promise.all([
        api.summary(),
        api.incidents({ limit: PAGE_SIZE, status: status || undefined }),
      ]);
      setSummary(nextSummary);
      setIncidents(page.data);
      setCursor(page.next_cursor);
      setError(null);
    } catch (caught) {
      if (caught instanceof ApiError && caught.unauthenticated) {
        setSession({ authenticated: false });
        return;
      }
      setError(caught instanceof ApiError ? caught.message : "The SOC data service did not respond.");
    } finally {
      setLoading(false);
      loadedOnce.current = true;
    }
  }, [status]);

  const loadDetail = useCallback(async (id: number) => {
    try {
      setDetail(await api.incident(id));
      setError(null);
    } catch (caught) {
      if (caught instanceof ApiError && caught.unauthenticated) {
        setSession({ authenticated: false });
        return;
      }
      setError(caught instanceof ApiError ? caught.message : "The SOC data service did not respond.");
    } finally {
      setLoading(false);
    }
  }, []);

  // Polling rather than websockets: the dashboard stays correct without a
  // streaming transport, and the backend needs no new infrastructure.
  useEffect(() => {
    if (!session?.authenticated) return;
    let cancelled = false;
    const tick = () => {
      if (cancelled) return;
      if (selected === null) void loadOverview();
      else void loadDetail(selected);
    };
    tick();
    const timer = setInterval(tick, REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [session?.authenticated, selected, loadOverview, loadDetail]);

  async function signIn(credential: string) {
    await api.signIn(credential);
    setLoading(true);
    setSession(await api.session());
  }

  async function signOut() {
    await api.signOut().catch(() => undefined);
    setSession({ authenticated: false });
    setSummary(null);
    setIncidents([]);
    setDetail(null);
  }

  function openIncident(id: number) {
    window.location.hash = `#/incidents/${id}`;
    setDetail(null);
    setLoading(true);
    setSelected(id);
  }

  function backToOverview() {
    window.location.hash = "";
    setSelected(null);
    setDetail(null);
  }

  async function loadMore() {
    if (!cursor) return;
    const page = await api.incidents({ limit: PAGE_SIZE, cursor, status: status || undefined });
    setIncidents((current) => [...current, ...page.data]);
    setCursor(page.next_cursor);
  }

  if (session === null) {
    return (
      <main className="mx-auto max-w-5xl px-4 py-10">
        <Skeleton rows={4} />
      </main>
    );
  }

  if (!session.authenticated) {
    return <SignIn onSignIn={signIn} />;
  }

  const criticalCount = summary?.incidents.critical ?? 0;

  return (
    <div className="min-h-dvh">
      <header className="sticky top-0 z-10 border-b border-line bg-surface/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5">
          <button
            type="button"
            onClick={backToOverview}
            className="font-mono text-[13px] font-semibold tracking-tight text-ink"
          >
            SENTINELMESH
          </button>
          <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-faint">SOC</span>

          <div className="ml-auto flex flex-wrap items-center gap-x-4 gap-y-2">
            <p
              className={`flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wide ${
                criticalCount > 0 ? "text-critical" : "text-ok"
              }`}
            >
              <span aria-hidden="true">{criticalCount > 0 ? "▲" : "●"}</span>
              {criticalCount > 0 ? `${criticalCount} critical` : "operational"}
            </p>
            <button
              type="button"
              onClick={toggleTheme}
              className="rounded border border-line px-2 py-1 font-mono text-[11px] text-muted hover:bg-sunken"
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
            >
              {theme === "dark" ? "Light" : "Dark"}
            </button>
            <span className="hidden font-mono text-[11px] text-faint sm:inline">{session.operator}</span>
            <button
              type="button"
              onClick={signOut}
              className="rounded border border-line px-2 py-1 font-mono text-[11px] text-muted hover:bg-sunken"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1600px] px-4 py-4">
        {error && !loadedOnce.current ? (
          <ErrorState
            title="Unable to load SOC data"
            body={error}
            onRetry={() => {
              setLoading(true);
              if (selected === null) void loadOverview();
              else void loadDetail(selected);
            }}
          />
        ) : selected !== null ? (
          detail ? (
            <IncidentView incident={detail} onBack={backToOverview} />
          ) : (
            <Panel title="Loading incident">
              <Skeleton rows={6} />
            </Panel>
          )
        ) : loading || !summary ? (
          <div className="space-y-4">
            <Skeleton rows={2} />
            <Panel title="Incidents">
              <Skeleton rows={5} />
            </Panel>
          </div>
        ) : (
          <Overview
            summary={summary}
            incidents={incidents}
            status={status}
            onStatusChange={(next) => {
              setStatus(next);
              setLoading(true);
            }}
            onSelect={openIncident}
            onLoadMore={loadMore}
            hasMore={cursor !== null}
          />
        )}

        {error && loadedOnce.current && (
          <p role="status" className="mt-3 text-center font-mono text-[11px] text-faint">
            Last refresh failed — retrying automatically.
          </p>
        )}
      </main>
    </div>
  );
}
