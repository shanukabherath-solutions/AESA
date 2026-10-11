import { Fragment, useState } from "react";
import type { Gate, Scan } from "../types";
import { StatusPill } from "./ui";

const counts = (s: Scan) =>
  [["critical", s.critical], ["high", s.high], ["medium", s.medium], ["low", s.low]].filter(([, n]) => (n as number) > 0)
    .map(([k, n]) => `${n} ${k}`).join(", ") || "none";

/** Latest result per tool for the current patch, with the gate verdict on top. */
export function ScanTable({ scans, gate }: { scans: Scan[]; gate: Gate }) {
  const [open, setOpen] = useState<number | null>(null);
  const latest = new Map<string, Scan>();
  scans.filter((s) => s.phase === "proposal").forEach((s) => latest.set(s.tool, s));
  const rows = [...latest.values()];

  return (
    <div>
      <div className={`mb-3 rounded-md border px-3 py-2 ${gate.passed ? "border-ok/40 bg-ok/10 text-ok" : "border-deny/40 bg-deny/10 text-deny"}`}>
        <p className="font-medium">{gate.passed ? "Security gate passed" : "Security gate blocking approval"}</p>
        {!gate.passed && <ul className="mt-1 list-disc pl-5 text-sm">{gate.reasons.map((r) => <li key={r}>{r}</li>)}</ul>}
      </div>
      <table className="w-full text-sm">
        <thead><tr className="border-b border-rule"><th className="th">Check</th><th className="th">Result</th><th className="th">Findings</th><th className="th">Summary</th></tr></thead>
        <tbody>
          {rows.map((s) => (
            <Fragment key={s.id}>
              <tr className="cursor-pointer border-b border-rule/60 hover:bg-hover" onClick={() => setOpen(open === s.id ? null : s.id)}>
                <td className="td font-mono text-xs">{s.tool}{gate.required.includes(s.tool) ? "" : " (optional)"}</td>
                <td className="td"><StatusPill status={s.status} /></td>
                <td className="td text-dim">{counts(s)}</td>
                <td className="td text-dim">{s.summary}</td>
              </tr>
              {open === s.id && s.findings.length > 0 && (
                <tr key={`${s.id}-f`} className="bg-ink"><td colSpan={4} className="px-3 py-2">
                  <ul className="space-y-1 font-mono text-xs">
                    {s.findings.slice(0, 20).map((f, i) => (
                      <li key={i} className="text-dim"><span className="text-warn">{f.severity}</span> {f.rule} {f.file ? `${f.file}:${f.line ?? ""}` : ""} — {f.message}</li>
                    ))}
                  </ul>
                </td></tr>
              )}
            </Fragment>
          ))}
          {gate.missing.map((m) => (
            <tr key={m} className="border-b border-rule/60"><td className="td font-mono text-xs">{m}</td><td className="td"><StatusPill status="PENDING" text="Not run" /></td><td className="td" /><td className="td text-dim">Not run against the current patch</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
