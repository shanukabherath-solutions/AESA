import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Empty, ErrorNote, PageHeader, Panel, StatusPill } from "../components/ui";
import { timeAgo } from "../lib/format";
import { useLoad } from "../lib/hooks";
import { ApiError, api } from "../services/api";
import { useAuth } from "../services/auth";
import type { Repo, Task } from "../types";

const DEFAULT_PROMPT = "Analyze this repository and identify a security issue in the authentication module. Propose a safe fix and run all available tests.";

export function Tasks() {
  const { can } = useAuth();
  const nav = useNavigate();
  const repos = useLoad(() => api.get<Repo[]>("/repositories"), []);
  const tasks = useLoad(() => api.get<Task[]>("/agent/tasks"), [], 4000);
  const [repoId, setRepoId] = useState<number | "">("");
  const [prompt, setPrompt] = useState(DEFAULT_PROMPT);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const chosen = repoId || repos.data?.[0]?.id || "";

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      const t = await api.post<Task>("/agent/tasks", { repository_id: chosen, prompt });
      nav(`/tasks/${t.id}`);
    } catch (err) { setError(err instanceof ApiError ? err.headline : "Failed to start the task"); }
    finally { setBusy(false); }
  }

  return (
    <>
      <PageHeader title="Agent tasks" subtitle="The agent inspects, proposes, and tests. It cannot commit, merge, or deploy." />
      {can("create_task") ? (
        <Panel title="New task" className="mb-5">
          <form onSubmit={submit} className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-[14rem_1fr]">
              <label><span className="mb-1 block text-xs text-dim">Repository</span>
                <select className="input" value={chosen} onChange={(e) => setRepoId(+e.target.value)}>{repos.data?.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</select></label>
              <label><span className="mb-1 block text-xs text-dim">What should the agent do?</span>
                <textarea className="input min-h-[84px]" value={prompt} onChange={(e) => setPrompt(e.target.value)} minLength={5} maxLength={4000} required /></label>
            </div>
            <ErrorNote message={error} />
            <button className="btn btn-primary" disabled={busy || !chosen}>{busy ? "Starting…" : "Start task"}</button>
          </form>
        </Panel>
      ) : <p className="mb-5 rounded-md border border-rule bg-panel px-4 py-3 text-dim">Your role ({"viewer or approver"}) can watch tasks but not start them.</p>}
      <Panel title="All tasks">
        <ErrorNote message={tasks.error} />
        {tasks.data?.length ? (
          <table className="w-full text-sm">
            <thead><tr className="border-b border-rule"><th className="th">Task</th><th className="th">Repository</th><th className="th">Status</th><th className="th">Risk</th><th className="th">Started</th></tr></thead>
            <tbody>
              {tasks.data.map((t) => (
                <tr key={t.id} className="border-b border-rule/60 hover:bg-hover">
                  <td className="td"><Link to={`/tasks/${t.id}`} className="hover:underline">#{t.id} {t.prompt.slice(0, 70)}</Link></td>
                  <td className="td text-dim">{t.repository}</td>
                  <td className="td"><StatusPill status={t.status} /></td>
                  <td className="td">{t.risk_level ? <StatusPill status={t.risk_level} /> : <span className="text-faint">—</span>}</td>
                  <td className="td text-dim">{timeAgo(t.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <Empty>No tasks yet.</Empty>}
      </Panel>
    </>
  );
}
