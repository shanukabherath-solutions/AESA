"""Language / framework / test-file detection over files exposed by a PathGuard."""
from __future__ import annotations

import json
from collections import Counter

from app.repository.paths import PathGuard

EXT_LANG = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".go": "Go", ".rs": "Rust", ".java": "Java", ".rb": "Ruby", ".php": "PHP", ".sh": "Shell",
    ".yml": "YAML", ".yaml": "YAML", ".md": "Markdown", ".toml": "TOML", ".json": "JSON",
}
FRAMEWORK_HINTS = {
    "flask": "Flask", "django": "Django", "fastapi": "FastAPI", "sqlalchemy": "SQLAlchemy",
    "pytest": "pytest", "react": "React", "express": "Express", "vite": "Vite", "next": "Next.js",
}


def _is_test(rel: str) -> bool:
    low = rel.lower()
    name = low.rsplit("/", 1)[-1]
    return (
        low.startswith(("tests/", "test/"))
        or name.startswith("test_")
        or name.endswith(("_test.py", ".test.ts", ".test.tsx", ".test.js", ".spec.ts", ".spec.js"))
    )


def inspect(guard: PathGuard, max_files: int = 5000) -> dict[str, object]:
    files = list(guard.iter_files(".", max_files=max_files))
    langs: Counter[str] = Counter()
    for f in files:
        ext = "." + f.rsplit(".", 1)[-1].lower() if "." in f.rsplit("/", 1)[-1] else ""
        if ext in EXT_LANG and EXT_LANG[ext] not in {"Markdown", "JSON", "YAML", "TOML"}:
            langs[EXT_LANG[ext]] += 1
    frameworks: set[str] = set()
    for manifest in ("requirements.txt", "pyproject.toml", "package.json"):
        if manifest in files:
            try:
                text = guard.read_text(manifest, 200_000).lower()
            except Exception:  # noqa: S112 - unreadable manifest: skip framework hints
                continue
            if manifest == "package.json":
                try:
                    pkg = json.loads(text)
                    text = " ".join({**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}.keys())
                except ValueError:  # malformed package.json
                    text = ""
            for hint, label in FRAMEWORK_HINTS.items():
                if hint in text:
                    frameworks.add(label)
    return {
        "file_count": len(files),
        "languages": dict(langs.most_common()),
        "frameworks": sorted(frameworks),
        "test_files": [f for f in files if _is_test(f)][:100],
        "has_python": "Python" in langs or "requirements.txt" in files or "pyproject.toml" in files,
        "has_node": "package.json" in files,
        "files": files,
    }
