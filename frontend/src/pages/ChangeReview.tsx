import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { DiffViewer } from "../components/DiffViewer";
import { GateTracker } from "../components/GateTracker";
import { ScanTable } from "../components/ScanTable";
import { ErrorNote, Mono, PageHeader, Panel, StatusPill } from "../components/ui";
import { useLoad } from "../lib/hooks";
import { ApiError, api } from "../services/api";
import { useAuth } from "../services/auth";
import type { ApprovalDetail, CIRun, Scan } from "../types";

interface DiffResp { diff: string; patch_sha256: string | null; explanation: string | null }

export function ChangeReview() {
  const id = Number(useParams().id);
  const { can, user } = useAuth();
  const ap = useLoad(() => api.get<ApprovalDetail>(`/approvals/${id}`), [id], 3000);
  const taskId = ap.data?.task_id;
  const diff = useLoad(() => (taskId ? api.get<DiffResp>(`/tasks/${taskId}/diff`) : Promise.resolve(null)), [taskId]);
  const scans = useLoad(() => (taskId ? api.get<{ scans: Scan[] }>(`/security/scans/${taskId}`) : Promise.resolve(null)), [taskId, ap.data?.gate.passed]);
  const ci = useLoad(() => (taskId ? api.get<{ runs: CIRun[] }>(`/ci/runs/${taskId}`) : Promise.resolve(null)), [taskId, ap.data?.task.status]);
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [reasons, setReasons] = useState<string[]>([]);

  const a = ap.data;
  if (ap.error) return <ErrorNote message={ap.error} />;
  if (!a) return <p className="text-dim">Loading…</p>;
  const t = a.task;
  const isPatch = a.type === "PATCH";
  const pending = a.status === "PENDING";
  const selfAuthored = isPatch && user?.username === t.created_by;
  const blocked = isPatch && !a.gate.passed;
  const canDecide = can("approve") && pending && !selfAuthored;

  async function act(kind: "approve" | "reject" | "request-changes") {
    setBusy(true); setErr(null); setReasons([]);
    try {
      await api.post(`/approvals/${id}/${kind}`, { patch_sha256: a!.patch_sha256, comment: comment || undefined });
      setComment(""); ap.reload();
    } catch (e) {
      if (e instanceof ApiError) { setErr(e.headline); setReasons(e.reasons); } else setErr("Request failed");
    } finally { setBusy(false); }
  }
  async function deploy() {
    setBusy(true); setErr(null);
    try { await api.post(`/deployments/${t.id}/execute`); ap.reload(); }
    catch (e) { setErr(e instanceof ApiError ? e.headline : "Deployment failed"); }
    finally { setBusy(false); }
  }

  return (
    <>
      <PageHeader title={isPatch ? `Review patch for task ${t.id}` : `Deployment approval for task ${t.id}`}
        subtitle={`${t.repository} · proposed by the agent for ${t.created_by}`}
        action={<div className="flex items-center gap-2">{a.risk_level && <StatusPill status={a.risk_level} text={`${a.risk_level.toLowerCase()} risk`} />}<StatusPill status={a.status} /></div>} />
      <Panel className="mb-5"><GateTracker status={t.status} /></Panel>

      <div className="grid gap-5 lg:grid-cols-3">
        <div className="space-y-5 lg:col-span-2">
          <Panel title="What the agent wants to change">
            <p className="font-medium">{t.summary}</p>
            {t.explanation && <p className="mt-2 whitespace-pre-wrap text-dim">{t.explanation}</p>}
            <p className="mt-3 text-sm text-dim">Request: {a.summary}</p>
          </Panel>
          {isPatch && <Panel title="Before and after">{diff.data ? <DiffViewer diff={diff.data.diff} /> : <p className="text-dim">Loading…</p>}</Panel>}
          <Panel title="Test and security results">
            {scans.data ? <ScanTable scans={scans.data.scans} gate={a.gate} /> : <p className="text-dim">Loading…</p>}
          </Panel>
          {!isPatch && ci.data && (
            <Panel title="CI">
              {ci.data.runs[0] ? <div className="space-y-2"><StatusPill status={ci.data.runs[0].status} text={`${ci.data.runs[0].provider} CI ${ci.data.runs[0].status.toLowerCase()}`} />
                <ul className="text-sm">{ci.data.runs[0].jobs.map((j) => <li key={j.name} className="flex items-center gap-2 py-0.5"><Mono>{j.name}</Mono><span className="text-dim">{j.conclusion}</span></li>)}</ul></div> : <p className="text-dim">No CI run.</p>}
            </Panel>
          )}
        </div>

        <div className="space-y-5">
          <Panel title="Files affected">
            {t.files_changed.length ? <ul className="space-y-1.5 text-sm">{t.files_changed.map((f) => <li key={f.path} className="flex items-center justify-between gap-2"><Mono>{f.path}</Mono><span className="font-mono text-xs"><span className="text-ok">+{f.additions}</span> <span className="text-deny">−{f.deletions}</span></span></li>)}</ul> : <p className="text-dim">None.</p>}
            {t.branch_name && <p className="mt-3 text-xs text-dim">Branch <Mono>{t.branch_name}</Mono> (never the default branch)</p>}
            {a.patch_sha256 && <p className="mt-2 text-xs text-dim">Patch hash <Mono>{a.patch_sha256.slice(0, 16)}</Mono>. Your decision is bound to this exact patch.</p>}
          </Panel>

          <Panel title="Decision">
            {pending ? (
              <div className="space-y-3">
                {!can("approve") && <p className="text-dim">Your role can view this request but not decide on it.</p>}
                {selfAuthored && <p className="text-warn">You started this task, so someone else must approve it.</p>}
                {blocked && <p className="text-deny">Approval is blocked until the security gate passes.</p>}
                <label className="block"><span className="mb-1 block text-xs text-dim">Comment {isPatch ? "(required to request changes)" : "(optional)"}</span>
                  <textarea className="input min-h-[70px]" value={comment} onChange={(e) => setComment(e.target.value)} maxLength={2000} /></label>
                <ErrorNote message={err} />
                {reasons.length > 0 && <ul className="list-disc pl-5 text-sm text-deny">{reasons.map((r) => <li key={r}>{r}</li>)}</ul>}
                <div className="flex flex-wrap gap-2">
                  <button className="btn btn-ok" disabled={!canDecide || blocked || busy} onClick={() => act("approve")}>{isPatch ? "Approve" : "Approve deployment"}</button>
                  <button className="btn btn-danger" disabled={!canDecide || busy} onClick={() => act("reject")}>Reject</button>
                  {isPatch && <button className="btn" disabled={!canDecide || busy || !comment.trim()} onClick={() => act("request-changes")}>Request changes</button>}
                </div>
                {isPatch && <p className="text-xs text-faint">Approving commits the patch to a feature branch and starts CI. It does not touch the default branch and does not deploy.</p>}
              </div>
            ) : (
              <div className="space-y-2 text-sm">
                <p>Decision: <StatusPill status={a.status} /></p>
                {a.comment && <p className="text-dim">“{a.comment}”</p>}
                {!isPatch && t.status === "DEPLOY_APPROVED" && can("approve") && (
                  <><ErrorNote message={err} /><button className="btn btn-primary" disabled={busy} onClick={deploy}>Run deployment</button></>
                )}
                {t.status === "DEPLOYED" && <p className="text-ok">Deployed.</p>}
                <Link className="text-gate hover:underline" to={`/tasks/${t.id}`}>View task</Link>
              </div>
            )}
          </Panel>
        </div>
      </div>
    </>
  );
}
