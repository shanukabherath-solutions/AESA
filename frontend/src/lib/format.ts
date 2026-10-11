import type { TaskStatus } from "../types";

export type Tone = "ok" | "warn" | "deny" | "gate" | "dim";

export const STATUS_TONE: Record<string, Tone> = {
  PASSED: "ok", EXECUTED: "ok", ALLOW: "ok", ALLOWED: "ok", APPROVED: "ok", APPLIED: "ok", CI_PASSED: "ok", DEPLOYED: "ok",
  READY_FOR_DEPLOYMENT: "ok", DEPLOY_APPROVED: "ok", OK: "ok",
  AWAITING_APPROVAL: "warn", PENDING: "warn", PROPOSED: "warn", CHANGES_REQUESTED: "warn",
  CI_RUNNING: "gate", ANALYZING: "gate", RUNNING: "gate", QUEUED: "gate",
  FAILED: "deny", ERROR: "deny", DENIED: "deny", DENY: "deny", REJECTED: "deny", CI_FAILED: "deny", FAILED_SAFELY: "deny",
  CANCELLED: "dim", DRAFT: "dim", SKIPPED: "dim", ANALYSIS_ONLY: "dim", IDLE: "dim", LOW: "ok", MEDIUM: "warn", HIGH: "deny",
};

export const toneOf = (s: string | null | undefined): Tone => (s && STATUS_TONE[s]) || "dim";

export function label(s: string): string {
  const t = s.toLowerCase().replace(/_/g, " ");
  return t.charAt(0).toUpperCase() + t.slice(1);
}

export function timeAgo(iso: string | null, now: number = Date.now()): string {
  if (!iso) return "never";
  const sec = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

export const ACTIVE: TaskStatus[] = ["DRAFT", "ANALYZING", "CI_RUNNING", "APPLIED", "APPROVED"];
export const isActive = (s: TaskStatus) => ACTIVE.includes(s);

/** The happy-path sequence with the two human gates marked. Order mirrors the backend state machine. */
export const PIPELINE: { status: TaskStatus; label: string; gateAfter?: string }[] = [
  { status: "ANALYZING", label: "Analyzing" },
  { status: "PROPOSED", label: "Proposed" },
  { status: "AWAITING_APPROVAL", label: "Review", gateAfter: "Human approval" },
  { status: "APPROVED", label: "Approved" },
  { status: "APPLIED", label: "Applied" },
  { status: "CI_RUNNING", label: "CI" },
  { status: "READY_FOR_DEPLOYMENT", label: "Ready", gateAfter: "Deployment approval" },
  { status: "DEPLOY_APPROVED", label: "Cleared" },
  { status: "DEPLOYED", label: "Deployed" },
];

/** Index of the current step in PIPELINE (CI_PASSED folds into CI); off-path states return -1. */
export function pipelineIndex(s: TaskStatus): number {
  const mapped: TaskStatus = s === "CI_PASSED" ? "CI_RUNNING" : s === "DRAFT" ? "ANALYZING" : s;
  return PIPELINE.findIndex((p) => p.status === mapped);
}
