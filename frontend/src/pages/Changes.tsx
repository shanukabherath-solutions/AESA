import { Link } from "react-router-dom";
import { Empty, ErrorNote, PageHeader, Panel, StatusPill } from "../components/ui";
import { label, timeAgo } from "../lib/format";
import { useLoad } from "../lib/hooks";
import { api } from "../services/api";
import type { ApprovalWithTask } from "../types";

export function Changes() {
  const { data, error } = useLoad(() => api.get<ApprovalWithTask[]>("/approvals"), [], 4000);
  const pending = data?.filter((a) => a.status === "PENDING") ?? [];
  const decided = data?.filter((a) => a.status !== "PENDING") ?? [];

  const Row = ({ a }: { a: ApprovalWithTask }) => (
    <tr className="border-b border-rule/60 hover:bg-hover">
      <td className="td"><Link className="hover:underline" to={`/changes/${a.id}`}>{a.type === "PATCH" ? "Patch" : "Deployment"} for task #{a.task_id}</Link><p className="text-xs text-dim">{a.summary}</p></td>
      <td className="td text-dim">{a.task?.repository}</td>
      <td className="td text-dim">{a.task?.files_changed.map((f) => f.path).join(", ")}</td>
      <td className="td">{a.risk_level ? <StatusPill status={a.risk_level} /> : null}</td>
      <td className="td"><StatusPill status={a.status} text={label(a.status)} /></td>
      <td className="td text-dim">{timeAgo(a.decided_at ?? a.requested_at)}</td>
    </tr>
  );
  const head = <thead><tr className="border-b border-rule"><th className="th">Request</th><th className="th">Repository</th><th className="th">Files</th><th className="th">Risk</th><th className="th">State</th><th className="th">When</th></tr></thead>;

  return (
    <>
      <PageHeader title="Proposed changes" subtitle="Nothing is applied or deployed until a person approves it here." />
      <ErrorNote message={error} />
      <Panel title={`Waiting for a decision (${pending.length})`} className="mb-5">
        {pending.length ? <table className="w-full text-sm">{head}<tbody>{pending.map((a) => <Row key={a.id} a={a} />)}</tbody></table> : <Empty>Nothing is waiting for approval.</Empty>}
      </Panel>
      <Panel title="Decided">
        {decided.length ? <table className="w-full text-sm">{head}<tbody>{decided.map((a) => <Row key={a.id} a={a} />)}</tbody></table> : <Empty>No decisions yet.</Empty>}
      </Panel>
    </>
  );
}
