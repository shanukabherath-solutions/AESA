import { Fragment, useState } from "react";
import { Empty, ErrorNote, PageHeader, Panel, StatusPill } from "../components/ui";
import { useLoad } from "../lib/hooks";
import { api, qs } from "../services/api";
import { useAuth } from "../services/auth";
import type { AuditEntry } from "../types";

const STATUSES = ["", "EXECUTED", "DENIED", "REJECTED", "FAILED", "APPROVED", "OK", "FAILED_SAFELY", "DEPLOYED"];

export function AuditLogs() {
  const { user } = useAuth();
  const [f, setF] = useState({ action: "", repository: "", agent: "", status: "", date_from: "", date_to: "", q: "" });
  const [open, setOpen] = useState<number | null>(null);
  const [verify, setVerify] = useState<string | null>(null);
  const logs = useLoad(() => api.get<{ total: number; items: AuditEntry[] }>(`/audit-logs${qs({ ...f, limit: 200 })}`), [JSON.stringify(f)], 5000);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });

  async function runVerify() {
    const r = await api.get<{ ok: boolean; entries: number; first_bad_id: number | null }>("/audit-logs/verify");
    setVerify(r.ok ? `Chain intact across ${r.entries} entries.` : `Chain broken at entry ${r.first_bad_id}.`);
  }

  return (
    <>
      <PageHeader title="Audit logs" subtitle="Append-only and hash-chained. Secrets are redacted before anything is stored."
        action={user?.role === "ADMIN" ? <button className="btn" onClick={runVerify}>Verify chain</button> : undefined} />
      {verify && <p className={`mb-4 rounded-md border px-3 py-2 ${verify.includes("intact") ? "border-ok/40 bg-ok/10 text-ok" : "border-deny/40 bg-deny/10 text-deny"}`}>{verify}</p>}
      <Panel className="mb-5">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <label><span className="mb-1 block text-xs text-dim">Action</span><input className="input" placeholder="tool_call, login…" value={f.action} onChange={set("action")} /></label>
          <label><span className="mb-1 block text-xs text-dim">Repository</span><input className="input" value={f.repository} onChange={set("repository")} /></label>
          <label><span className="mb-1 block text-xs text-dim">Agent</span><input className="input" placeholder="AESA" value={f.agent} onChange={set("agent")} /></label>
          <label><span className="mb-1 block text-xs text-dim">Status</span><select className="input" value={f.status} onChange={set("status")}>{STATUSES.map((s) => <option key={s} value={s}>{s || "Any"}</option>)}</select></label>
          <label><span className="mb-1 block text-xs text-dim">From</span><input className="input" type="datetime-local" onChange={(e) => setF({ ...f, date_from: e.target.value ? new Date(e.target.value).toISOString() : "" })} /></label>
          <label><span className="mb-1 block text-xs text-dim">To</span><input className="input" type="datetime-local" onChange={(e) => setF({ ...f, date_to: e.target.value ? new Date(e.target.value).toISOString() : "" })} /></label>
          <label className="sm:col-span-2"><span className="mb-1 block text-xs text-dim">Search tool or result</span><input className="input" value={f.q} onChange={set("q")} /></label>
        </div>
      </Panel>
      <ErrorNote message={logs.error} />
      <Panel title={`${logs.data?.total ?? 0} entries`}>
        {logs.data?.items.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-rule"><th className="th">Time (UTC)</th><th className="th">Who</th><th className="th">Action</th><th className="th">Permission</th><th className="th">Status</th><th className="th">Result</th></tr></thead>
              <tbody>
                {logs.data.items.map((e) => (
                  <Fragment key={e.id}>
                    <tr className="cursor-pointer border-b border-rule/60 hover:bg-hover" onClick={() => setOpen(open === e.id ? null : e.id)}>
                      <td className="td whitespace-nowrap font-mono text-xs text-dim">{e.timestamp.replace("T", " ").replace("Z", "")}</td>
                      <td className="td text-dim">{e.agent ?? e.user ?? "system"}{e.agent && e.user ? <span className="text-faint"> for {e.user}</span> : null}</td>
                      <td className="td"><code className="text-gate">{e.tool ?? e.action}</code>{e.tool && <span className="text-faint"> · {e.action}</span>}</td>
                      <td className="td">{e.permission_decision ? <StatusPill status={e.permission_decision} /> : <span className="text-faint">—</span>}</td>
                      <td className="td">{e.status ? <StatusPill status={e.status} /> : null}</td>
                      <td className="td max-w-[22rem] truncate text-dim">{e.result}</td>
                    </tr>
                    {open === e.id && (
                      <tr className="bg-ink"><td colSpan={6} className="px-4 py-3">
                        <pre className="overflow-x-auto whitespace-pre-wrap text-xs text-dim">{JSON.stringify({ ...e, entry_hash: undefined }, null, 2)}</pre>
                        <p className="mt-2 font-mono text-[11px] text-faint">hash {e.entry_hash}</p>
                      </td></tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty>No entries match these filters.</Empty>}
      </Panel>
    </>
  );
}
