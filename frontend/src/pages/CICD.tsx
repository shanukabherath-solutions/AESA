import { useState } from "react";
import { Empty, ErrorNote, Mono, PageHeader, Panel, StatusPill } from "../components/ui";
import { GateTracker } from "../components/GateTracker";
import { Link } from "react-router-dom";
import { label, timeAgo } from "../lib/format";
import { useLoad } from "../lib/hooks";
import { ApiError, api } from "../services/api";
import { useAuth } from "../services/auth";
import type { CIRun, Deployment, Scan, Task } from "../types";

interface CIResp { runs: CIRun[]; deployment: Deployment | null; pr_url: string | null; task_status: string | null }

export function CICD() {
  const { can } = useAuth();
  const tasks = useLoad(() => api.get<Task[]>("/agent/tasks"), [], 5000);
  const relevant = tasks.data?.filter((t) => t.branch_name) ?? [];
  const [sel, setSel] = useState<number | null>(null);
  const task = relevant.find((t) => t.id === sel) ?? relevant[0];
  const ci = useLoad(() => (task ? api.get<CIResp>(`/ci/runs/${task.id}`) : Promise.resolve(null)), [task?.id, task?.status], 4000);
  const scans = useLoad(() => (task ? api.get<{ scans: Scan[] }>(`/security/scans/${task.id}`) : Promise.resolve(null)), [task?.id, task?.status]);
  const [err, setErr] = useState<string | null>(null);
  const run = ci.data?.runs[0];

  async function refresh() {
    setErr(null);
    try { await api.post(`/ci/runs/${task!.id}/refresh`); ci.reload(); tasks.reload(); }
    catch (e) { setErr(e instanceof ApiError ? e.headline : "Refresh failed"); }
  }

  return (
    <>
      <PageHeader title="CI/CD" subtitle="Pipeline, security scans, and deployment state for agent branches."
        action={relevant.length > 1 ? <select className="input w-64" value={task?.id ?? ""} onChange={(e) => setSel(+e.target.value)}>{relevant.map((t) => <option key={t.id} value={t.id}>#{t.id} {t.branch_name}</option>)}</select> : undefined} />
      <ErrorNote message={tasks.error ?? err} />
      {!task ? <Empty>No approved changes yet. CI starts once a person approves a patch.</Empty> : (
        <div className="space-y-5">
          <Panel><GateTracker status={task.status} /></Panel>
          <div className="grid gap-5 lg:grid-cols-3">
            <Panel title="Latest pipeline" className="lg:col-span-2" action={run?.provider === "github" && <button className="btn" onClick={refresh}>Refresh from GitHub</button>}>
              {run ? (
                <div className="space-y-4">
                  <div className="flex flex-wrap items-center gap-3"><StatusPill status={run.status} /><span className="text-dim">{run.provider === "github" ? "GitHub Actions" : "Local CI"} · <Mono>{run.branch}</Mono> · {timeAgo(run.updated_at)}</span>
                    {run.url && <a className="text-gate hover:underline" href={run.url} target="_blank" rel="noreferrer noopener">Open run</a>}</div>
                  {run.jobs.length > 0 && <table className="w-full text-sm"><thead><tr className="border-b border-rule"><th className="th">Job</th><th className="th">Result</th><th className="th">Detail</th></tr></thead>
                    <tbody>{run.jobs.map((j) => <tr key={j.name} className="border-b border-rule/60"><td className="td font-mono text-xs">{j.name}</td><td className="td"><StatusPill status={j.conclusion?.toUpperCase() ?? j.status.toUpperCase()} /></td><td className="td text-dim">{j.summary}</td></tr>)}</tbody></table>}
                  <div><p className="mb-1 text-xs text-dim">Build log</p><pre className="max-h-72 overflow-auto rounded-md bg-ink p-3 text-xs text-dim">{run.logs || "No output yet."}</pre></div>
                </div>
              ) : <Empty>No pipeline run recorded for this task.</Empty>}
            </Panel>
            <div className="space-y-5">
              <Panel title="Deployment">
                {ci.data?.deployment ? (
                  <div className="space-y-2 text-sm">
                    <StatusPill status={ci.data.deployment.status === "DEPLOYED" ? "DEPLOYED" : ci.data.deployment.status === "APPROVED" ? "DEPLOY_APPROVED" : "PENDING"} text={label(ci.data.deployment.status)} />
                    <p className="text-dim">Target: {ci.data.deployment.target} · {ci.data.deployment.environment}</p>
                    {ci.data.deployment.status === "PENDING_APPROVAL" && <p className="text-dim">Waiting for a separate deployment approval.</p>}
                    {can("approve") && ["READY_FOR_DEPLOYMENT", "DEPLOY_APPROVED"].includes(task.status) && <Link className="btn btn-primary" to="/changes">Go to approvals</Link>}
                  </div>
                ) : <p className="text-dim">Not ready. CI must pass first.</p>}
                {ci.data?.pr_url && <p className="mt-3 text-sm"><a className="text-gate hover:underline" href={ci.data.pr_url} target="_blank" rel="noreferrer noopener">Pull request</a></p>}
              </Panel>
              <Panel title="Security scans (proposal and CI)">
                <ul className="space-y-1.5 text-sm">
                  {scans.data?.scans.map((s) => <li key={s.id} className="flex items-center justify-between gap-2"><span className="font-mono text-xs">{s.tool} <span className="text-faint">{s.phase}</span></span><StatusPill status={s.status} /></li>)}
                </ul>
              </Panel>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
