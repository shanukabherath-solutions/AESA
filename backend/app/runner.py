"""Background execution (thread pool in production, inline for deterministic tests)."""
from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from app.config import get_settings

log = logging.getLogger(__name__)
_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="aesa")


def submit(fn: Callable[..., Any], *args: Any) -> None:
    def safe() -> None:
        try:
            fn(*args)
        except Exception:  # noqa: BLE001
            log.exception("background job %s failed", getattr(fn, "__name__", fn))

    if get_settings().background_mode == "inline":
        safe()
    else:
        _pool.submit(safe)
