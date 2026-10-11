import { PIPELINE, pipelineIndex } from "../lib/format";
import type { TaskStatus } from "../types";
import { StatusPill } from "./ui";

const Lock = ({ open }: { open: boolean }) => (
  <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden>
    <rect x="3" y="7" width="10" height="7" rx="1.5" />
    <path d={open ? "M5.5 7V5a2.5 2.5 0 0 1 4.9-.7" : "M5.5 7V5a2.5 2.5 0 0 1 5 0v2"} />
  </svg>
);

/** The task's progress through the state machine. Barriers mark the two points a human must open. */
export function GateTracker({ status, compact = false }: { status: TaskStatus; compact?: boolean }) {
  const idx = pipelineIndex(status);
  const offPath = idx === -1;

  return (
    <div className="overflow-x-auto pb-1" aria-label={`Progress: ${status}`}>
      <ol className="flex min-w-max items-start">
        {PIPELINE.map((step, i) => {
          const done = !offPath && i < idx;
          const current = !offPath && i === idx;
          const nodeClass = current
            ? "border-gate bg-gate text-ink ring-4 ring-gate/20"
            : done ? "border-ok bg-ok/20 text-ok" : "border-rule bg-ink text-faint";
          const gateOpen = idx > i;
          const gateWaiting = idx === i && !!step.gateAfter && (step.status === "AWAITING_APPROVAL" || step.status === "READY_FOR_DEPLOYMENT");
          return (
            <li key={step.status} className="flex items-start">
              <div className="flex w-[76px] flex-col items-center gap-1.5 text-center">
                <span className={`flex h-6 w-6 items-center justify-center rounded-full border-2 text-[10px] font-semibold ${nodeClass}`}>
                  {done ? "✓" : i + 1}
                </span>
                {!compact && <span className={`text-xs ${current ? "font-semibold text-text" : done ? "text-dim" : "text-faint"}`}>{step.label}</span>}
              </div>
              {i < PIPELINE.length - 1 && (
                step.gateAfter ? (
                  <div className="mt-[2px] flex flex-col items-center" title={step.gateAfter}>
                    <span className={`flex h-5 items-center gap-1 rounded border px-1.5 text-[10px] font-medium ${
                      gateOpen ? "border-ok/50 text-ok" : gateWaiting ? "border-warn text-warn bg-warn/10 animate-pulse" : "border-rule text-faint"}`}>
                      <Lock open={gateOpen} />{!compact && step.gateAfter}
                    </span>
                  </div>
                ) : (
                  <span className={`mt-3 h-0.5 w-6 ${done ? "bg-ok/50" : "bg-rule"}`} />
                )
              )}
            </li>
          );
        })}
      </ol>
      {offPath && <div className="mt-3"><StatusPill status={status} /></div>}
    </div>
  );
}
