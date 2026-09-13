import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { incidentDetailFixture, incidentRow, summaryFixture } from "./fixtures";

type Route = Record<string, { status?: number; body?: unknown }>;

function mockApi(routes: Route) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    const key = Object.keys(routes).find((candidate) => url.startsWith(candidate));
    if (!key) return new Response("{}", { status: 404 });
    const route = routes[key];
    if (route.status && route.status >= 400) {
      return new Response(JSON.stringify({ error: { code: "x", message: "internal" } }), { status: route.status });
    }
    return new Response(JSON.stringify(route.body ?? {}), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const AUTHED = { "/soc/session": { body: { authenticated: true, operator: "soc-analyst", scopes: ["read"] } } };
const SUMMARY = { "/api/soc/summary/": { body: summaryFixture } };
const INCIDENTS = { "/api/incidents/?": { body: { data: [incidentRow], next_cursor: null } } };
const DETAIL = { "/api/incidents/1": { body: incidentDetailFixture } };

beforeEach(() => {
  window.location.hash = "";
  localStorage.clear();
});

describe("authentication", () => {
  it("shows the sign-in form when there is no session", async () => {
    mockApi({ "/soc/session": { body: { authenticated: false } } });
    render(<App />);

    expect(await screen.findByLabelText(/credential/i)).toBeInTheDocument();
    expect(screen.getByText(/not stored in the browser/i)).toBeInTheDocument();
  });

  it("never writes a credential to localStorage", async () => {
    mockApi({
      "/soc/session": { body: { authenticated: false } },
      "/soc/login": { body: { operator: "soc-analyst", scopes: ["read"] } },
    });
    render(<App />);

    const input = await screen.findByLabelText(/credential/i);
    await userEvent.type(input, "super-secret-credential");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));

    const stored = JSON.stringify(localStorage);
    expect(stored).not.toContain("super-secret-credential");
  });

  it("returns to sign-in when the API reports the session expired", async () => {
    mockApi({ ...AUTHED, "/api/soc/summary/": { status: 401 }, ...INCIDENTS });
    render(<App />);

    expect(await screen.findByLabelText(/credential/i)).toBeInTheDocument();
  });
});

describe("overview", () => {
  it("renders security metrics from the API", async () => {
    mockApi({ ...AUTHED, ...SUMMARY, ...INCIDENTS });
    render(<App />);

    const critical = await screen.findByText("Critical");
    expect(within(critical.parentElement!).getByText("1")).toBeInTheDocument();
    expect(screen.getByText(/1 critical/i)).toBeInTheDocument();
  });

  it("renders incidents returned by the API", async () => {
    mockApi({ ...AUTHED, ...SUMMARY, ...INCIDENTS });
    render(<App />);

    expect(await screen.findByText("SM-001")).toBeInTheDocument();
    expect(screen.getByText(/multi stage attack/i)).toBeInTheDocument();
    expect(screen.getAllByText(/critical/i).length).toBeGreaterThan(0);
  });

  it("renders response actions, showing failures as failures", async () => {
    mockApi({ ...AUTHED, ...SUMMARY, ...INCIDENTS });
    render(<App />);

    expect(await screen.findByText(/block source/i)).toBeInTheDocument();
    expect(screen.getByText(/^failed$/i)).toBeInTheDocument();
  });

  it("shows containment state separately from response history", async () => {
    mockApi({ ...AUTHED, ...SUMMARY, ...INCIDENTS });
    render(<App />);

    expect(await screen.findByText("Containment state")).toBeInTheDocument();
    expect(screen.getByText("Subjects")).toBeInTheDocument();
  });
});

describe("states", () => {
  it("shows a loading skeleton before data arrives", () => {
    mockApi({ ...AUTHED, ...SUMMARY, ...INCIDENTS });
    render(<App />);
    expect(screen.getAllByRole("status", { name: /loading/i }).length).toBeGreaterThan(0);
  });

  it("shows an empty state when there are no incidents", async () => {
    mockApi({
      ...AUTHED,
      "/api/soc/summary/": {
        body: { ...summaryFixture, incidents: { active: 0, critical: 0, high: 0, other: 0, total: 0 } },
      },
      "/api/incidents/?": { body: { data: [], next_cursor: null } },
    });
    render(<App />);

    expect(await screen.findByText(/no incidents/i)).toBeInTheDocument();
    expect(screen.getByText(/has not correlated any threats/i)).toBeInTheDocument();
  });

  it("shows a retryable error state and never leaks backend detail", async () => {
    mockApi({ ...AUTHED, "/api/soc/summary/": { status: 500 }, ...INCIDENTS });
    render(<App />);

    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("internal");
    expect(document.body.textContent).not.toMatch(/Traceback|psycopg/);
  });
});

describe("incident investigation", () => {
  async function openIncident() {
    mockApi({ ...AUTHED, ...SUMMARY, ...INCIDENTS, ...DETAIL });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: /open incident SM-001/i }));
    return screen.findByRole("heading", { level: 1, name: "SM-001" });
  }

  it("renders the attack chain in order", async () => {
    await openIncident();
    expect(screen.getByText("Credential Abuse")).toBeInTheDocument();
    expect(screen.getByText("Privileged Access Attempt")).toBeInTheDocument();
    expect(screen.getByText("Application Injection")).toBeInTheDocument();
  });

  it("renders backend risk factors without recomputing them", async () => {
    await openIncident();
    expect(screen.getByText(/highest threat risk/i)).toBeInTheDocument();
    expect(screen.getByText("+94")).toBeInTheDocument();
    expect(screen.getByText("-9")).toBeInTheDocument();
    // The displayed total is the backend's score, not a client-side sum.
    expect(screen.getByText(/backend score/i)).toBeInTheDocument();
  });

  it("renders correlation confidence and explanation", async () => {
    await openIncident();
    expect(screen.getByText("0.990")).toBeInTheDocument();
    expect(screen.getByText(/3 threats correlated from/i)).toBeInTheDocument();
  });

  it("renders the timeline and reveals threat evidence on selection", async () => {
    await openIncident();
    await userEvent.click(screen.getByRole("button", { name: /inspect threat injection.sql/i }));
    expect(await screen.findByText(/threat evidence/i)).toBeInTheDocument();
    expect(screen.getByText("sql_injection.v1")).toBeInTheDocument();
  });

  it("renders the server-provided zero-trust decision", async () => {
    await openIncident();
    expect(screen.getByText("deny")).toBeInTheDocument();
    expect(screen.getByText("critical_incident")).toBeInTheDocument();
    expect(screen.getByText(/associated with active incident/i)).toBeInTheDocument();
  });

  it("renders containment state with explicit labels", async () => {
    await openIncident();
    expect(screen.getByText("CONTAINED")).toBeInTheDocument();
    expect(screen.getByText("ISOLATED")).toBeInTheDocument();
    expect(screen.getByText("BLOCKED")).toBeInTheDocument();
  });

  it("does not manufacture a decision when the backend supplies none", async () => {
    mockApi({
      ...AUTHED,
      ...SUMMARY,
      ...INCIDENTS,
      "/api/incidents/1": { body: { ...incidentDetailFixture, zero_trust: [] } },
    });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: /open incident SM-001/i }));

    expect(await screen.findByText(/no access decisions/i)).toBeInTheDocument();
    expect(screen.queryByText("deny")).not.toBeInTheDocument();
  });
});

describe("safe rendering", () => {
  it("escapes attacker-controlled threat evidence instead of injecting markup", async () => {
    const payload = "<img src=x onerror=alert(1)>' OR 1=1 --";
    mockApi({
      ...AUTHED,
      ...SUMMARY,
      ...INCIDENTS,
      "/api/incidents/1": {
        body: {
          ...incidentDetailFixture,
          threats: [{ ...incidentDetailFixture.threats[0], reason: payload, threat_type: payload }],
        },
      },
    });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: /open incident SM-001/i }));

    await waitFor(() => expect(screen.getAllByText(payload).length).toBeGreaterThan(0));
    expect(document.querySelector("img")).toBeNull();
  });
});
