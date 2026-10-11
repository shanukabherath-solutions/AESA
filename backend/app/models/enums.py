from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    VIEWER = "VIEWER"
    DEVELOPER = "DEVELOPER"
    APPROVER = "APPROVER"
    ADMIN = "ADMIN"


class PermissionLevel(str, Enum):
    READ_ONLY = "READ_ONLY"
    PROPOSE_CHANGE = "PROPOSE_CHANGE"
    APPROVED_CHANGE = "APPROVED_CHANGE"
    DEPLOY = "DEPLOY"


LEVEL_ORDER: dict[PermissionLevel, int] = {
    PermissionLevel.READ_ONLY: 0,
    PermissionLevel.PROPOSE_CHANGE: 1,
    PermissionLevel.APPROVED_CHANGE: 2,
    PermissionLevel.DEPLOY: 3,
}


class TaskStatus(str, Enum):
    DRAFT = "DRAFT"
    ANALYZING = "ANALYZING"
    PROPOSED = "PROPOSED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"
    APPLIED = "APPLIED"
    CI_RUNNING = "CI_RUNNING"
    CI_PASSED = "CI_PASSED"
    CI_FAILED = "CI_FAILED"
    READY_FOR_DEPLOYMENT = "READY_FOR_DEPLOYMENT"
    DEPLOY_APPROVED = "DEPLOY_APPROVED"
    DEPLOYED = "DEPLOYED"
    # terminal, non-happy-path states
    ANALYSIS_ONLY = "ANALYSIS_ONLY"
    FAILED_SAFELY = "FAILED_SAFELY"
    CANCELLED = "CANCELLED"


class ApprovalType(str, Enum):
    PATCH = "PATCH"
    DEPLOY = "DEPLOY"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"


class ActionStatus(str, Enum):
    EXECUTED = "EXECUTED"
    DENIED = "DENIED"
    REJECTED = "REJECTED"  # malformed / invalid arguments
    FAILED = "FAILED"


class ScanStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"  # tool could not run: fail closed
    SKIPPED = "SKIPPED"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_ORDER = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class CIStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"


class DeploymentStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    DEPLOYED = "DEPLOYED"
    FAILED = "FAILED"
