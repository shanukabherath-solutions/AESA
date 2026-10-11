import type { Action, PolicyDecision } from "../types";
import { StatusPill } from "./ui";

/** Concise action log: what the agent did and why. No hidden reasoning is stored or shown. */
export function ActionList({ actions, decisions }: { actions: Action[]; decisions: PolicyDecision[] }) {
  const byTool = new Map<string, PolicyDecision[]>();
  decisions.forEach((d) => byTool.set(d.tool, [...(byTool.get(d.tool) ?? []), d]));
  if (!actions.length) return <p className="text-dim">No actions yet.</p>;
  return (
    <ol className="divide-y divide-rule/60">
      {actions.map((a) => (
        <li key={a.id} className="grid grid-cols-[2rem_1fr_auto] gap-3 py-2.5">
          <span className="pt-0.5 text-right font-mono text-xs text-faint">{a.step}</span>
          <div className="min-w-0">
            <p><code className="text-gate">{a.tool}</code> <span className="text-dim">{a.reason}</span></p>
            <p className={`mt-0.5 break-words text-sm ${a.status === "DENIED" ? "text-deny" : "text-dim"}`}>{a.result_summary}</p>
          </div>
          <div className="flex flex-col items-end gap-1">
            <StatusPill status={a.status} />
            <span className="font-mono text-xs text-faint">{a.duration_ms != null ? `${(a.duration_ms / 1000).toFixed(1)}s` : ""}{a.exit_code != null ? ` · exit ${a.exit_code}` : ""}</span>
          </div>
        </li>
      ))}
    </ol>
  );
}
