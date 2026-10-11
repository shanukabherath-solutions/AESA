import { Link } from "react-router-dom";
import { GateTracker } from "../components/GateTracker";
import { Empty, ErrorNote, PageHeader, Panel, Stat, StatusPill } from "../components/ui";
import { label, timeAgo } from "../lib/format";
import { useLoad } from "../lib/hooks";
import { api } from "../services/api";
import type { Summary } from "../types";

export function Dashboard() {
  const { data: s, error } = useLoad(() => api.get<Summary>("/dashboard/summary"), [], 4000);
  if (error) return <ErrorNote message={error} />;
  if (!s) return <p className="text-dim">Loading…</p>;
  const t = s.current_task;

  return (
    <>
      <PageHeader title="Dashboard" subtitle="What the agent is doing, and what is waiting on a person." />
      <div className="mb-5 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Panel><Stat name="Agent" value={label(s.agent_status)} tone={s.agent_status === "RUNNING" ? "gate" : "dim"} /><p className="mt-1 text-xs text-faint">{s.ai_provider} provider · {s.sandbox_backend} sandbox</p></Panel>
        <Panel><Stat name="Awaiting your approval" value={s.pending_approvals} tone={s.pending_approvals ? "warn" : "dim"} />
          <Link className="mt-1 inline-block text-xs text-gate hover:underline" to="/changes">Open proposed changes</Link></Panel>
        <Panel><Stat name="Security gate" value={s.security?.passed == null ? "No patch yet" : s.security.passed ? "Passing" : "Blocking"} tone={s.security?.passed == null ? "dim" : s.security.passed ? "ok" : "deny"} />
          {s.security && !s.security.passed && s.security.reasons[0] && <p className="mt-1 text-xs text-faint">{s.security.reasons[0]}</p>}</Panel>
        <Panel><Stat name="Latest CI" value={s.ci ? label(s.ci.status) : "No runs"} tone={s.ci?.status === "PASSED" ? "ok" : s.ci?.status === "FAILED" ? "deny" : "dim"} />
          {s.ci && <p className="mt-1 text-xs text-faint">{s.ci.provider} · {timeAgo(s.ci.updated_at)}</p>}</Panel>
      </div>

      <Panel title="Current task" className="mb-5" action={t && <StatusPill status={t.status} />}>
        {t ? (
          <div className="space-y-4">
            <GateTracker status={t.status} />
            <p className="text-dim"><Link to={`/tasks/${t.id}`} className="text-text hover:underline">Task {t.id}</Link> on {t.repository} by {t.created_by}: {t.prompt.slice(0, 160)}</p>
          </div>
        ) : <Empty>No tasks yet. Start one from Agent tasks.</Empty>}
      </Panel>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title="Latest actions">
          {s.latest_actions.length ? (
            <ul className="space-y-2">
              {s.latest_actions.map((a, i) => (
                <li key={i} className="flex items-start justify-between gap-3">
                  <p className="min-w-0 text-sm"><code className="text-gate">{a.tool}</code> <span className="text-dim">{a.result_summary}</span></p>
                  <StatusPill status={a.status} />
                </li>
              ))}
            </ul>
          ) : <Empty>No actions recorded.</Empty>}
        </Panel>
        <Panel title="Recent tasks">
          {s.latest_tasks.length ? (
            <ul className="divide-y divide-rule/60">
              {s.latest_tasks.map((x) => (
                <li key={x.id} className="flex items-center justify-between gap-3 py-2">
                  <Link to={`/tasks/${x.id}`} className="min-w-0 truncate hover:underline">#{x.id} {x.prompt}</Link>
                  <StatusPill status={x.status} />
                </li>
              ))}
            </ul>
          ) : <Empty>Nothing here yet.</Empty>}
        </Panel>
      </div>
    </>
  );
}
