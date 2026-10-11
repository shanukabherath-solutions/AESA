import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ActionList } from "../components/ActionList";
import { GateTracker } from "../components/GateTracker";
import { ErrorNote, Mono, PageHeader, Panel, StatusPill } from "../components/ui";
import { isActive } from "../lib/format";
import { useLoad } from "../lib/hooks";
import { ApiError, api } from "../services/api";
import { useAuth } from "../services/auth";
import type { Action, Approval, PolicyDecision, Task } from "../types";

export function TaskDetail() {
  const id = Number(useParams().id);
  const { can } = useAuth();
  const task = useLoad(() => api.get<Task>(`/agent/tasks/${id}`), [id], 2000);
  const live = task.data ? isActive(task.data.status) : true;
  const acts = useLoad(() => api.get<{ actions: Action[]; policy_decisions: PolicyDecision[] }>(`/tasks/${id}/actions`), [id, task.data?.status], live ? 2000 : null);
  const approvals = useLoad(() => api.get<(Approval)[]>("/approvals"), [id, task.data?.status]);
  const [err, setErr] = useState<string | null>(null);
  const t = task.data;
  const myApproval = approvals.data?.find((a) => a.task_id === id && a.status === "PENDING");
  const denied = acts.data?.policy_decisions.filter((d) => d.decision === "DENY") ?? [];

  async function cancel() {
    setErr(null);
    try { await api.post(`/agent/tasks/${id}/cancel`); task.reload(); }
    catch (e) { setErr(e instanceof ApiError ? e.headline : "Could not cancel"); }
  }

  if (task.error) return <ErrorNote message={task.error} />;
  if (!t) return <p className="text-dim">Loading…</p>;

  return (
    <>
      <PageHeader title={`Task ${t.id}`} subtitle={`${t.repository} · started by ${t.created_by} · ${t.ai_provider} provider · ${t.permission_level}`}
        action={<div className="flex items-center gap-2">
          <StatusPill status={t.status} />
          {myApproval && <Link className="btn btn-primary" to={`/changes/${myApproval.id}`}>Review change</Link>}
          {can("create_task") && !["REJECTED", "CHANGES_REQUESTED", "CI_FAILED", "DEPLOYED", "ANALYSIS_ONLY", "FAILED_SAFELY", "CANCELLED"].includes(t.status) && <button className="btn btn-danger" onClick={cancel}>Cancel</button>}
        </div>} />
      <ErrorNote message={err} />
      <Panel className="mb-5"><GateTracker status={t.status} /></Panel>

      <div className="grid gap-5 lg:grid-cols-3">
        <div className="space-y-5 lg:col-span-2">
          <Panel title="Request"><p className="whitespace-pre-wrap">{t.prompt}</p></Panel>
          <Panel title="Agent actions" action={<span className="text-xs text-dim">{acts.data?.actions.length ?? 0} actions · {denied.length} denied</span>}>
            <ActionList actions={acts.data?.actions ?? []} decisions={acts.data?.policy_decisions ?? []} />
          </Panel>
        </div>
        <div className="space-y-5">
          <Panel title="Outcome">
            <dl className="space-y-3 text-sm">
              {t.summary && <div><dt className="text-xs text-dim">Summary</dt><dd>{t.summary}</dd></div>}
              {t.explanation && <div><dt className="text-xs text-dim">Findings and fix</dt><dd className="whitespace-pre-wrap">{t.explanation}</dd></div>}
              {t.risk_level && <div><dt className="text-xs text-dim">Risk</dt><dd><StatusPill status={t.risk_level} /></dd></div>}
              {t.files_changed.length > 0 && <div><dt className="text-xs text-dim">Files affected</dt><dd className="space-y-1">{t.files_changed.map((f) => <div key={f.path}><Mono>{f.path}</Mono> <span className="font-mono text-xs text-ok">+{f.additions}</span> <span className="font-mono text-xs text-deny">−{f.deletions}</span></div>)}</dd></div>}
              {t.branch_name && <div><dt className="text-xs text-dim">Branch</dt><dd><Mono>{t.branch_name}</Mono></dd></div>}
              {t.pr_url && <div><dt className="text-xs text-dim">Pull request</dt><dd><a className="text-gate hover:underline" href={t.pr_url} target="_blank" rel="noreferrer noopener">{t.pr_url}</a></dd></div>}
              {t.feedback && <div><dt className="text-xs text-dim">Reviewer feedback</dt><dd>{t.feedback}</dd></div>}
              {t.failure_reason && <div><dt className="text-xs text-dim">Stopped safely because</dt><dd className="text-deny">{t.failure_reason}</dd></div>}
              {!t.summary && !t.failure_reason && <p className="text-dim">The agent is still working.</p>}
            </dl>
          </Panel>
          {denied.length > 0 && (
            <Panel title="Blocked by policy">
              <ul className="space-y-2 text-sm">{denied.map((d) => <li key={d.id}><code className="text-deny">{d.tool}</code> <span className="text-dim">{d.rule}: {d.reason}</span></li>)}</ul>
            </Panel>
          )}
        </div>
      </div>
    </>
  );
}
