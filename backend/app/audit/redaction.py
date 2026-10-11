"""Secret redaction for everything that is logged, stored, or shown to the model/UI."""
from __future__ import annotations

import re
from typing import Any

# High-confidence credential formats (safe to apply to source code shown to the model).
_TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[A-Za-z0-9+/=\s]*")),
    ("api-key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("github-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}")),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("bearer", re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/\-]{12,}=*")),
]

# Lower-confidence: assignments like password=..., token: ..., Authorization: ...
_KV_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|token|passw(?:or)?d|passwd|pwd|authorization)"
    r"(\s*[:=]\s*)(['\"]?)([^\s'\",;]{4,})"
)

_SENSITIVE_KEY = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|authorization|private[_-]?key|credential|cookie|auth_header)"
)

REDACTED = "[REDACTED]"
MARKER_PREFIX = "[REDACTED:"
MAX_STR = 4000


def redact_text(text: str, *, aggressive: bool = False) -> str:
    """Redact credentials from text. `aggressive` also masks key=value assignments."""
    for label, pat in _TOKEN_PATTERNS:
        text = pat.sub(f"{MARKER_PREFIX}{label}]", text)
    if aggressive:
        text = _KV_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{MARKER_PREFIX}secret]", text)
    return text


def redact_obj(obj: Any, *, _depth: int = 0) -> Any:
    """Recursively redact a JSON-like structure (keys with sensitive names are masked wholesale)."""
    if _depth > 8:
        return "[TRUNCATED]"
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            ks = str(k)
            if _SENSITIVE_KEY.search(ks) and not isinstance(v, (dict, list)):
                out[ks] = REDACTED
            else:
                out[ks] = redact_obj(v, _depth=_depth + 1)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, _depth=_depth + 1) for v in obj[:200]]
    if isinstance(obj, str):
        s = redact_text(obj, aggressive=True)
        return s if len(s) <= MAX_STR else s[:MAX_STR] + "…[truncated]"
    return obj


def contains_redaction_marker(text: str) -> bool:
    return MARKER_PREFIX in text
