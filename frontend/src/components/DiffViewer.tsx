import { useMemo } from "react";
import { parseUnifiedDiff } from "../lib/diff";

const ROW: Record<string, string> = {
  add: "bg-ok/10 text-ok/90", del: "bg-deny/10 text-deny/90", ctx: "text-dim", hunk: "bg-gate/10 text-gate",
};
const SIGN: Record<string, string> = { add: "+", del: "−", ctx: " ", hunk: "" };

export function DiffViewer({ diff }: { diff: string }) {
  const files = useMemo(() => parseUnifiedDiff(diff), [diff]);
  if (!files.length) return <p className="text-dim">No diff available.</p>;
  return (
    <div className="space-y-4">
      {files.map((f) => (
        <div key={f.path} className="overflow-hidden rounded-md border border-rule">
          <div className="flex items-center justify-between bg-raised px-3 py-2 text-xs">
            <code className="text-text">{f.path}</code>
            <span className="font-mono"><span className="text-ok">+{f.additions}</span> <span className="text-deny">−{f.deletions}</span></span>
          </div>
          <div className="overflow-x-auto bg-ink">
            <table className="w-full border-collapse font-mono text-xs leading-5">
              <tbody>
                {f.lines.map((l, i) => (
                  <tr key={i} className={ROW[l.kind]}>
                    <td className="w-10 select-none px-2 text-right text-faint">{l.oldNo ?? ""}</td>
                    <td className="w-10 select-none px-2 text-right text-faint">{l.newNo ?? ""}</td>
                    <td className="w-4 select-none text-center">{SIGN[l.kind]}</td>
                    <td className="whitespace-pre pr-4">{l.kind === "hunk" ? l.text : l.text || " "}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </div>
  );
}
