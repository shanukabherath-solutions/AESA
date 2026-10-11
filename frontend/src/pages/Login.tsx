import { useState, type FormEvent } from "react";
import { ApiError } from "../services/api";
import { useAuth } from "../services/auth";
import { ErrorNote } from "../components/ui";

export function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try { await login(username, password); }
    catch (err) { setError(err instanceof ApiError ? err.headline : "Could not reach the server"); }
    finally { setBusy(false); }
  }

  return (
    <div className="flex min-h-full items-center justify-center p-6">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-lg border border-rule bg-panel p-6">
        <div>
          <h1 className="text-lg font-semibold">Sign in to AESA</h1>
          <p className="mt-1 text-dim">The agent proposes. People approve.</p>
        </div>
        <label className="block"><span className="mb-1 block text-xs text-dim">Username</span>
          <input className="input" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus /></label>
        <label className="block"><span className="mb-1 block text-xs text-dim">Password</span>
          <input className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
        <ErrorNote message={error} />
        <button className="btn btn-primary w-full" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
    </div>
  );
}
