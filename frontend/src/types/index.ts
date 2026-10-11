export type Role = "VIEWER" | "DEVELOPER" | "APPROVER" | "ADMIN";
export interface User { id: number; username: string; role: Role; is_active: boolean }

export type TaskStatus =
  | "DRAFT" | "ANALYZING" | "PROPOSED" | "AWAITING_APPROVAL" | "APPROVED" | "REJECTED" | "CHANGES_REQUESTED"
  | "APPLIED" | "CI_RUNNING" | "CI_PASSED" | "CI_FAILED" | "READY_FOR_DEPLOYMENT" | "DEPLOY_APPROVED" | "DEPLOYED"
  | "ANALYSIS_ONLY" | "FAILED_SAFELY" | "CANCELLED";

export interface FileChange { path: string; status: string; additions: number; deletions: number }
export interface Task {
  id: number; repository_id: number; repository: string; created_by: string; prompt: string; status: TaskStatus;
  permission_level: string; ai_provider: string; branch_name: string | null; risk_level: string | null; summary: string | null;
  files_changed: FileChange[]; patch_sha256: string | null; failure_reason: string | null; pr_url: string | null;
  commit_sha: string | null; created_at: string; updated_at: string; explanation?: string | null; feedback?: string | null;
}
export interface Repo {
  id: number; name: string; root_path: string; default_branch: string; github_repo: string | null;
  allowed_paths: string[]; protected_paths: string[]; protected_branches: string[];
}
export interface RepoStats {
  repository: string; default_branch: string; protected_branches: string[]; file_count: number;
  languages: Record<string, number>; frameworks: string[]; test_files: string[];
}
export interface Action {
  id: number; step: number; tool: string; arguments: Record<string, unknown>; reason: string; status: string;
  result_summary: string; exit_code: number | null; duration_ms: number | null; created_at: string;
}
export interface PolicyDecision { id: number; tool: string; actor: string; decision: "ALLOW" | "DENY"; rule: string; reason: string }
export interface Finding { severity: string; rule: string; message: string; file: string | null; line: number | null }
export interface Scan {
  id: number; tool: string; status: "PASSED" | "FAILED" | "ERROR" | "SKIPPED"; critical: number; high: number; medium: number; low: number;
  summary: string; findings: Finding[]; duration_s: number; phase: string;
}
export interface Gate { passed: boolean; required: string[]; missing: string[]; reasons: string[] }
export interface Approval {
  id: number; task_id: number; type: "PATCH" | "DEPLOY"; status: string; summary: string; risk_level: string | null;
  patch_sha256: string | null; requested_at: string; decided_at: string | null; comment: string | null;
}
export interface ApprovalWithTask extends Approval { task: Task | null }
export interface ApprovalDetail extends Approval { task: Task; gate: Gate }
export interface CIJob { name: string; status: string; conclusion: string; summary?: string }
export interface CIRun { id: number; provider: string; status: string; url: string | null; branch: string | null; commit_sha: string | null; jobs: CIJob[]; logs: string; updated_at: string }
export interface Deployment { id: number; status: string; target: string; environment: string; details: Record<string, unknown>; executed_at: string | null }
export interface AuditEntry {
  id: number; timestamp: string; user: string | null; agent: string | null; repository: string | null; task_id: number | null;
  action: string; tool: string | null; arguments: Record<string, unknown>; permission_decision: string | null; result: string | null;
  status: string | null; exit_code: number | null; duration_ms: number | null; affected_files: string[]; approval_state: string | null;
  ip: string | null; session_id: string | null; entry_hash: string;
}
export interface Summary {
  agent_status: string; ai_provider: string; sandbox_backend: string; task_counts: Record<string, number>; pending_approvals: number;
  current_task: Task | null; security: { task_id: number; passed: boolean | null; reasons: string[] } | null; ci: CIRun | null;
  latest_tasks: Task[]; latest_actions: { task_id: number; tool: string; status: string; reason: string; result_summary: string }[];
}
