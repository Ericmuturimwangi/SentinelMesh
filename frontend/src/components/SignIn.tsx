import { useState, type FormEvent } from "react";

/** The credential is posted once and exchanged for an HttpOnly cookie. It is
 *  never stored in localStorage, never kept in module state, and never appears
 *  in the bundle. */
export function SignIn({ onSignIn }: { onSignIn: (credential: string) => Promise<void> }) {
  const [credential, setCredential] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onSignIn(credential);
      setCredential("");
    } catch {
      setError("That credential was not accepted, or it lacks read access.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto flex min-h-dvh max-w-md flex-col justify-center px-4 py-10">
      <h1 className="font-mono text-lg font-semibold tracking-tight text-ink">SentinelMesh SOC</h1>
      <p className="mt-1 text-[13px] text-muted">
        Sign in with a read-scoped SentinelMesh credential. It is exchanged for a session cookie and is not stored in
        the browser.
      </p>

      <form onSubmit={submit} className="mt-5 space-y-3">
        <div>
          <label htmlFor="credential" className="block font-mono text-[11px] uppercase tracking-wide text-muted">
            Credential
          </label>
          <input
            id="credential"
            type="password"
            autoComplete="current-password"
            value={credential}
            onChange={(event) => setCredential(event.target.value)}
            required
            className="mt-1 w-full rounded border border-line bg-raised px-3 py-2 font-mono text-[13px] text-ink"
            aria-describedby={error ? "credential-error" : undefined}
          />
        </div>
        {error && (
          <p id="credential-error" role="alert" className="text-[13px] text-critical">
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy || !credential.trim()}
          className="w-full rounded border border-accent/40 bg-accent-quiet px-3 py-2 text-[13px] font-medium text-accent disabled:opacity-50"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}
