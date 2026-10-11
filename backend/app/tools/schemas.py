"""Pydantic schemas for every model-callable tool. Anything not matching is rejected, not coerced."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ToolArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="", max_length=300, description="One short sentence: why this action is needed.")


class ListFilesArgs(ToolArgs):
    path: str = "."
    max_entries: int = Field(200, ge=1, le=1000)


class ReadFileArgs(ToolArgs):
    path: str = Field(min_length=1)
    start_line: int = Field(1, ge=1)
    max_lines: int = Field(400, ge=1, le=2000)


class SearchCodeArgs(ToolArgs):
    query: str = Field(min_length=2, max_length=200, description="Literal terms separated by '|'. Not a regex.")
    path: str = "."
    max_results: int = Field(50, ge=1, le=200)


class GitStatusArgs(ToolArgs):
    pass


class GitDiffArgs(ToolArgs):
    path: str | None = None
    staged: bool = False


class RunTestsArgs(ToolArgs):
    runner: Literal["auto", "pytest", "npm_test"] = "auto"
    path: str | None = None
    keyword: str | None = None


class RunLinterArgs(ToolArgs):
    linter: Literal["ruff", "mypy", "all"] = "all"


class RunSecurityScanArgs(ToolArgs):
    scanner: Literal["bandit", "gitleaks", "trivy", "npm_audit", "all"] = "all"


class FileEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=512)
    new_content: str = Field(max_length=200_000, description="Complete new content of the file.")


class CreatePatchArgs(ToolArgs):
    files: list[FileEdit] = Field(min_length=1, max_length=20)
    summary: str = Field(min_length=1, max_length=300, description="One-line title of the change.")
    explanation: str = Field(min_length=1, max_length=4000, description="What was wrong and why this fixes it.")
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]


class CreateBranchArgs(ToolArgs):
    pass


class RequestApprovalArgs(ToolArgs):
    summary: str = Field(min_length=1, max_length=1000)


class CreatePullRequestArgs(ToolArgs):
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(default="", max_length=4000)


TOOL_MODELS: dict[str, type[ToolArgs]] = {
    "list_files": ListFilesArgs,
    "read_file": ReadFileArgs,
    "search_code": SearchCodeArgs,
    "git_status": GitStatusArgs,
    "git_diff": GitDiffArgs,
    "run_tests": RunTestsArgs,
    "run_linter": RunLinterArgs,
    "run_security_scan": RunSecurityScanArgs,
    "create_patch": CreatePatchArgs,
    "create_branch": CreateBranchArgs,
    "request_approval": RequestApprovalArgs,
    "create_pull_request": CreatePullRequestArgs,
}

TOOL_DESCRIPTIONS = {
    "list_files": "List permitted repository files; at path '.' also returns detected languages, frameworks and test files.",
    "read_file": "Read a permitted text file (sensitive files are blocked).",
    "search_code": "Case-insensitive literal search across permitted files. Terms separated by '|'.",
    "git_status": "Show git status of the isolated workspace.",
    "git_diff": "Show the diff of the workspace against HEAD (or staged changes).",
    "run_tests": "Run the repository's test suite inside the sandbox.",
    "run_linter": "Run ruff and/or mypy inside the sandbox.",
    "run_security_scan": "Run bandit / gitleaks / trivy / npm audit inside the sandbox against the current workspace.",
    "create_patch": "Replace the proposed change set: give the COMPLETE new content for each modified file. The backend computes the diff.",
    "create_branch": "Create the proposal branch for this task (the backend chooses the name).",
    "request_approval": "Ask a human to review the proposed patch. Requires a patch and a full set of check results for it.",
    "create_pull_request": "Open a pull request for an APPROVED patch. Denied until a human has approved.",
}


def tool_catalogue() -> list[dict[str, Any]]:
    """JSON-schema tool catalogue handed to the provider (reason is part of every call)."""
    out: list[dict[str, Any]] = []
    for name, model in TOOL_MODELS.items():
        schema = model.model_json_schema()
        out.append({"name": name, "description": TOOL_DESCRIPTIONS[name], "parameters": schema})
    return out
