"""Tool implementations. Each is reached only via ToolExecutor (policy + validation + audit)."""
from __future__ import annotations

import hashlib
from typing import Any

from app.approvals.state import transition
from app.audit.redaction import contains_redaction_marker, redact_text
from app.models import Approval
from app.models.enums import ApprovalStatus, ApprovalType, ScanStatus, TaskStatus
from app.repository import inspector
from app.repository.git import run_git
from app.repository.paths import PathViolation
from app.sandbox.runner import execute
from app.security.gate import applicable_security_tools, derive_required_scans, evaluate_gate
from app.security.service import run_scan
from app.tools import schemas as S
from app.tools.context import ToolContext, ToolResult


def _tail(s: str, n: int = 2500) -> str:
    return redact_text(s[-n:], aggressive=True)


def list_files(ctx: ToolContext, a: S.ListFilesArgs) -> ToolResult:
    files = list(ctx.guard.iter_files(a.path, max_files=a.max_entries + 1))
    truncated = len(files) > a.max_entries
    data: dict[str, Any] = {"files": files[: a.max_entries], "truncated": truncated}
    if a.path in (".", "./", ""):
        info = inspector.inspect(ctx.guard)
        data.update({k: info[k] for k in ("languages", "frameworks", "test_files")})
    return ToolResult(True, f"{len(data['files'])} file(s) listed", data)


def read_file(ctx: ToolContext, a: S.ReadFileArgs) -> ToolResult:
    text = ctx.guard.read_text(a.path, ctx.settings.max_read_bytes)
    lines = text.splitlines()
    chunk = lines[a.start_line - 1 : a.start_line - 1 + a.max_lines]
    content = redact_text("\n".join(chunk))  # high-confidence credential formats only
    return ToolResult(True, f"read {a.path} ({len(chunk)} of {len(lines)} lines)",
                      {"path": a.path, "start_line": a.start_line, "total_lines": len(lines), "content": content})


def search_code(ctx: ToolContext, a: S.SearchCodeArgs) -> ToolResult:
    terms = [t.strip().lower() for t in a.query.split("|") if t.strip()][:10]
    if not terms:
        return ToolResult(False, "no search terms")
    hits: list[dict[str, Any]] = []
    for rel in ctx.guard.iter_files(a.path):
        try:
            text = ctx.guard.read_text(rel, ctx.settings.max_read_bytes)
        except PathViolation:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            low = line.lower()
            if any(t in low for t in terms):
                hits.append({"file": rel, "line": i, "text": redact_text(line.strip()[:200])})
                if len(hits) >= a.max_results:
                    return ToolResult(True, f"{len(hits)} match(es) (limit reached)", {"matches": hits})
    return ToolResult(True, f"{len(hits)} match(es)", {"matches": hits})


def _run_registered(ctx: ToolContext, key: str, args: dict[str, Any]) -> ToolResult:
    cmd = ctx.registry.plan(key, args)
    res = execute(cmd, ctx.workspace, ctx.sandbox, ctx.settings)
    return ToolResult(res.ok, f"{key} exit={res.exit_code}",
                      {"output": _tail(res.stdout, 6000), "stderr": _tail(res.stderr, 1500), "timed_out": res.timed_out},
                      exit_code=res.exit_code)


def git_status(ctx: ToolContext, a: S.GitStatusArgs) -> ToolResult:
    return _run_registered(ctx, "git_status", {})


def git_diff(ctx: ToolContext, a: S.GitDiffArgs) -> ToolResult:
    return _run_registered(ctx, "git_diff", {"path": a.path, "staged": a.staged})


def _scan_result(ctx: ToolContext, tools: list[str], extra: dict[str, Any] | None = None) -> ToolResult:
    rows, tails = [], {}
    for t in tools:
        row, tail = run_scan(ctx.db, ctx.task, t, ctx.workspace, ctx.sandbox, ctx.settings, extra_args=extra if t == "pytest" else None)
        rows.append(row)
        tails[t] = tail[-1200:]
    summary = "; ".join(f"{r.tool}: {r.status} ({r.summary})" for r in rows)
    ok = all(r.status == ScanStatus.PASSED.value for r in rows)
    data = {"results": [{"tool": r.tool, "status": r.status, "summary": r.summary, "critical": r.critical,
                         "high": r.high, "medium": r.medium, "low": r.low,
                         "findings": r.findings[:15]} for r in rows],
            "output_tail": {k: _tail(v, 1000) for k, v in tails.items()}}
    return ToolResult(ok, summary, data, exit_code=rows[-1].exit_code if rows else None)


def run_tests(ctx: ToolContext, a: S.RunTestsArgs) -> ToolResult:
    info = inspector.inspect(ctx.guard)
    runner = a.runner
    if runner == "auto":
        runner = "pytest" if info["has_python"] else "npm_test" if info["has_node"] else "pytest"
    extra = {"path": a.path, "keyword": a.keyword} if runner == "pytest" else None
    return _scan_result(ctx, [runner], extra)


def run_linter(ctx: ToolContext, a: S.RunLinterArgs) -> ToolResult:
    tools: list[str] = ["ruff", "mypy"] if a.linter == "all" else [a.linter]
    return _scan_result(ctx, tools)


def run_security_scan(ctx: ToolContext, a: S.RunSecurityScanArgs) -> ToolResult:
    info = inspector.inspect(ctx.guard)
    applicable = applicable_security_tools(info)
    if a.scanner == "all":
        tools = applicable
    elif a.scanner in applicable:
        tools = [a.scanner]
    else:
        return ToolResult(False, f"{a.scanner} is not applicable to this repository")
    return _scan_result(ctx, tools)


def create_branch(ctx: ToolContext, a: S.CreateBranchArgs) -> ToolResult:
    name = f"agent/proposal-{ctx.task.id}"
    run_git(ctx.workspace, "checkout", "-q", "-B", name)
    ctx.task.branch_name = name
    ctx.db.commit()
    return ToolResult(True, f"branch {name} created in the isolated workspace", {"branch": name})


def create_patch(ctx: ToolContext, a: S.CreatePatchArgs) -> ToolResult:
    s = ctx.settings
    seen: set[str] = set()
    for f in a.files:
        if f.path in seen:
            return ToolResult(False, f"duplicate path {f.path}")
        seen.add(f.path)
        if contains_redaction_marker(f.new_content):
            return ToolResult(False, f"{f.path}: content contains a [REDACTED:...] marker; "
                                     "never write redaction placeholders into files")
        if "\x00" in f.new_content or len(f.new_content.encode()) > s.max_patch_file_bytes:
            return ToolResult(False, f"{f.path}: invalid or oversized content")
    # Start from a clean tree so the patch is exactly the declared change set.
    run_git(ctx.workspace, "reset", "-q", "--hard", "HEAD")
    run_git(ctx.workspace, "clean", "-fdq")
    for f in a.files:
        ctx.guard.write_text(f.path, f.new_content)
    run_git(ctx.workspace, "add", "-A")
    patch = run_git(ctx.workspace, "diff", "--cached", "--no-color", "--no-ext-diff", "--no-textconv").stdout
    if not patch.strip():
        return ToolResult(False, "the proposed content is identical to the current files: no change")
    if len(patch.encode()) > 500_000:
        return ToolResult(False, "patch exceeds the 500 KB limit")
    numstat = run_git(ctx.workspace, "diff", "--cached", "--numstat").stdout.strip().splitlines()
    status = {ln.split("\t", 1)[1]: ln[0] for ln in run_git(ctx.workspace, "diff", "--cached", "--name-status").stdout.strip().splitlines()}
    changed = []
    for ln in numstat:
        add, dele, path = ln.split("\t", 2)
        changed.append({"path": path, "status": status.get(path, "M"),
                        "additions": int(add) if add.isdigit() else 0, "deletions": int(dele) if dele.isdigit() else 0})
    t = ctx.task
    t.patch_text, t.patch_sha256 = patch, hashlib.sha256(patch.encode()).hexdigest()
    t.files_changed, t.risk_level, t.summary, t.explanation = changed, a.risk_level, a.summary, a.explanation
    ctx.db.commit()
    if t.status == TaskStatus.ANALYZING.value:
        transition(ctx.db, t, TaskStatus.PROPOSED)
    return ToolResult(True, f"patch created: {len(changed)} file(s), sha256 {t.patch_sha256[:12]}",
                      {"files": changed, "patch_sha256": t.patch_sha256}, affected_files=[str(c["path"]) for c in changed])


def request_approval(ctx: ToolContext, a: S.RequestApprovalArgs) -> ToolResult:
    t = ctx.task
    if not t.patch_sha256 or not t.branch_name:
        return ToolResult(False, "create a proposal branch and a patch before requesting approval")
    info = inspector.inspect(ctx.guard)
    required = derive_required_scans(ctx.settings, info)
    gate = evaluate_gate(_scans(ctx), t.patch_sha256, required)
    if gate.missing:
        return ToolResult(False, "run these checks against the current patch first: " + ", ".join(gate.missing),
                          {"missing": gate.missing})
    t.required_scans = required
    ctx.db.add(Approval(task_id=t.id, type=ApprovalType.PATCH.value, status=ApprovalStatus.PENDING.value,
                        summary=a.summary, risk_level=t.risk_level, patch_sha256=t.patch_sha256))
    ctx.db.commit()
    if t.status == TaskStatus.ANALYZING.value:
        transition(ctx.db, t, TaskStatus.PROPOSED)
    transition(ctx.db, t, TaskStatus.AWAITING_APPROVAL)
    note = "" if gate.passed else " (security gate currently FAILING: approval will be blocked until fixed)"
    return ToolResult(True, "approval requested; waiting for a human decision" + note,
                      {"gate_passed": gate.passed, "gate_reasons": gate.reasons}, terminal=True)


def _scans(ctx: ToolContext) -> list[Any]:
    from sqlalchemy import select

    from app.models import SecurityScan

    return list(ctx.db.execute(select(SecurityScan).where(SecurityScan.task_id == ctx.task.id)).scalars())


def create_pull_request(ctx: ToolContext, a: S.CreatePullRequestArgs) -> ToolResult:
    # Reachable only if policy allowed it (i.e. a human approval exists). The real work lives in the applier.
    from app.approvals.applier import open_pull_request

    url = open_pull_request(ctx.db, ctx.settings, ctx.task, ctx.repo, a.title, a.body)
    return ToolResult(True, f"pull request {'opened' if url else 'not configured (no GitHub repo/token)'}", {"url": url})


HANDLERS = {
    "list_files": list_files, "read_file": read_file, "search_code": search_code, "git_status": git_status,
    "git_diff": git_diff, "run_tests": run_tests, "run_linter": run_linter,
    "run_security_scan": run_security_scan, "create_patch": create_patch, "create_branch": create_branch,
    "request_approval": request_approval, "create_pull_request": create_pull_request,
}
