import type { ReactNode } from "react";
import { label, toneOf, type Tone } from "../lib/format";

const TONE_CLASS: Record<Tone, string> = {
  ok: "text-ok border-ok/40 bg-ok/10",
  warn: "text-warn border-warn/40 bg-warn/10",
  deny: "text-deny border-deny/40 bg-deny/10",
  gate: "text-gate border-gate/40 bg-gate/10",
  dim: "text-dim border-rule bg-raised",
};

export function StatusPill({ status, text }: { status: string; text?: string }) {
  const tone = toneOf(status);
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium ${TONE_CLASS[tone]}`}>
      <span className={`h-1.5 w-1.5 rounded-full bg-current ${status === "ANALYZING" || status === "CI_RUNNING" ? "animate-pulse" : ""}`} />
      {text ?? label(status)}
    </span>
  );
}

export function Panel({ title, action, children, className = "" }: { title?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-lg border border-rule bg-panel ${className}`}>
      {(title || action) && (
        <header className="flex items-center justify-between gap-3 border-b border-rule px-4 py-2.5">
          <h2 className="text-sm font-semibold">{title}</h2>
          {action}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, action }: { title: string; subtitle?: string; action?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-0.5 text-dim">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="rounded-md border border-dashed border-rule px-4 py-6 text-center text-dim">{children}</p>;
}

export function ErrorNote({ message }: { message: string | null }) {
  if (!message) return null;
  return <p role="alert" className="rounded-md border border-deny/40 bg-deny/10 px-3 py-2 text-deny">{message}</p>;
}

export function Mono({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <code className={`rounded bg-ink px-1.5 py-0.5 text-xs text-dim ${className}`}>{children}</code>;
}

export function Stat({ name, value, tone }: { name: string; value: ReactNode; tone?: Tone }) {
  return (
    <div>
      <div className="text-xs text-dim">{name}</div>
      <div className={`mt-0.5 text-lg font-semibold ${tone ? TONE_CLASS[tone].split(" ")[0] : ""}`}>{value}</div>
    </div>
  );
}
