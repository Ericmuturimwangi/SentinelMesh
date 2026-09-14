import type { IncidentDetail, IncidentSummary, Page, SessionState, SocSummary } from "./types";

/** Same-origin calls only. The session cookie is HttpOnly, so nothing here
 *  reads or stores a credential -- it is attached by the browser. */

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
  get unauthenticated() {
    return this.status === 401;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      credentials: "same-origin",
      headers: { Accept: "application/json", ...(init?.body ? { "Content-Type": "application/json" } : {}) },
    });
  } catch {
    // Network-level failure: never surface an internal message.
    throw new ApiError(0, "The SOC data service could not be reached.");
  }

  if (!response.ok) {
    // Backend errors are already sanitised, but the dashboard still shows its
    // own wording rather than echoing a payload straight to the operator.
    const message =
      response.status === 401
        ? "Your session has expired."
        : response.status === 403
          ? "This credential is not permitted to read SOC data."
          : response.status === 404
            ? "That record no longer exists."
            : "The SOC data service returned an error.";
    throw new ApiError(response.status, message);
  }

  return (await response.json()) as T;
}

export const api = {
  session: () => request<SessionState>("/soc/session"),

  signIn: (credential: string) =>
    request<{ operator: string; scopes: string[] }>("/soc/login", {
      method: "POST",
      body: JSON.stringify({ credential }),
    }),

  signOut: () => request<{ signed_out: boolean }>("/soc/logout", { method: "POST" }),

  summary: () => request<SocSummary>("/api/soc/summary/"),

  incidents: (params: { limit?: number; cursor?: string; status?: string; sort?: string } = {}) => {
    const query = new URLSearchParams();
    if (params.limit) query.set("limit", String(params.limit));
    if (params.cursor) query.set("cursor", params.cursor);
    if (params.status) query.set("status", params.status);
    // Worst-first: the SOC queue is ordered by the backend, not re-sorted here.
    query.set("sort", params.sort ?? "risk");
    const suffix = query.toString();
    return request<Page<IncidentSummary>>(`/api/incidents/${suffix ? `?${suffix}` : ""}`);
  },

  incident: (id: number) => request<IncidentDetail>(`/api/incidents/${id}`),
};
