from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import runner
from app.agent.orchestrator import AgentOrchestrator
from app.api.serializers import action_out, decision_out, task_out
from app.approvals.state import InvalidTransition, is_terminal, transition
from app.audit import logger as audit
from app.auth.deps import Principal, require
from app.auth.security import Permission
from app.config import get_settings
from app.db import get_db
from app.models import AgentAction, AgentTask, PolicyDecision, Repository
from app.models.enums import PermissionLevel, Role, TaskStatus

router = APIRouter(prefix="/api", tags=["agent"])


class TaskCreate(BaseModel):
    repository_id: int
    prompt: str = Field(min_length=5, max_length=4000)


def _task(db: Session, task_id: int) -> AgentTask:
    t = db.get(AgentTask, task_id)
    if not t:
        raise HTTPException(404, "task not found")
    return t


@router.post("/agent/tasks", status_code=201)
def create_task(body: TaskCreate, db: Session = Depends(get_db), p: Principal = Depends(require(Permission.CREATE_TASK))) -> dict:
    repo = db.get(Repository, body.repository_id)
    if not repo:
        raise HTTPException(404, "repository not found")
    s = get_settings()
    # The agent's level is chosen by the backend, never by the caller, and never above PROPOSE_CHANGE.
    t = AgentTask(repository_id=repo.id, created_by=p.user.id, prompt=body.prompt, status=TaskStatus.DRAFT.value,
                  permission_level=PermissionLevel.PROPOSE_CHANGE.value, ai_provider=s.ai_provider)
    db.add(t)
    db.commit()
    audit.record(db, action="task_created", user=p.username, repository=repo.name, task_id=t.id,
                 arguments={"prompt": body.prompt[:500]}, status="DRAFT", ip=p.ip, session_id=p.session_id)
    runner.submit(AgentOrchestrator().run, t.id, p.ip, p.session_id)
    db.refresh(t)
    return task_out(t)


@router.get("/agent/tasks")
def list_tasks(limit: int = 50, db: Session = Depends(get_db), _: Principal = Depends(require(Permission.READ_DASHBOARD))) -> list[dict]:
    rows = db.execute(select(AgentTask).order_by(AgentTask.id.desc()).limit(min(limit, 200))).scalars()
    return [task_out(t) for t in rows]


@router.get("/agent/tasks/{task_id}")
def get_task(task_id: int, db: Session = Depends(get_db), _: Principal = Depends(require(Permission.READ_DASHBOARD))) -> dict:
    return task_out(_task(db, task_id), full=True)


@router.post("/agent/tasks/{task_id}/cancel")
def cancel_task(task_id: int, db: Session = Depends(get_db), p: Principal = Depends(require(Permission.CREATE_TASK))) -> dict:
    t = _task(db, task_id)
    if t.created_by != p.user.id and p.user.role != Role.ADMIN.value:
        raise HTTPException(403, "only the creator or an admin can cancel a task")
    if is_terminal(t):
        raise HTTPException(409, f"task is already {t.status}")
    try:
        transition(db, t, TaskStatus.CANCELLED)
    except InvalidTransition as exc:
        raise HTTPException(409, str(exc)) from exc
    audit.record(db, action="task_cancelled", user=p.username, repository=t.repository.name, task_id=t.id, status="CANCELLED",
                 ip=p.ip, session_id=p.session_id)
    return task_out(t)


@router.get("/tasks/{task_id}/actions")
def task_actions(task_id: int, db: Session = Depends(get_db), _: Principal = Depends(require(Permission.READ_DASHBOARD))) -> dict:
    _task(db, task_id)
    acts = db.execute(select(AgentAction).where(AgentAction.task_id == task_id).order_by(AgentAction.id)).scalars()
    decs = db.execute(select(PolicyDecision).where(PolicyDecision.task_id == task_id).order_by(PolicyDecision.id)).scalars()
    return {"actions": [action_out(a) for a in acts], "policy_decisions": [decision_out(d) for d in decs]}


@router.get("/tasks/{task_id}/diff")
def task_diff(task_id: int, db: Session = Depends(get_db), _: Principal = Depends(require(Permission.READ_DASHBOARD))) -> dict:
    t = _task(db, task_id)
    return {"task_id": t.id, "branch": t.branch_name, "patch_sha256": t.patch_sha256, "risk_level": t.risk_level,
            "summary": t.summary, "explanation": t.explanation, "files": t.files_changed, "diff": t.patch_text or ""}
