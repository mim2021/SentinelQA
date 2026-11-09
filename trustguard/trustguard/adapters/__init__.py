"""Thin per-platform adapters. Each one imports its SDK lazily, so installing one platform's
dependencies is enough to run that adapter."""

import os
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parents[2] / ".env"   # trustguard/.env


def load_env(path: Path = ENV_FILE) -> None:
    """Reads KEY=value lines from trustguard/.env into the environment, without overriding
    variables that are already set (so a secrets manager or the shell always wins)."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def require(*names: str) -> None:
    """Stops with a readable message instead of a KeyError when a setting is missing."""
    missing = [n for n in names if not os.environ.get(n) or "replace" in os.environ[n] or set(os.environ[n]) == {"0"}]
    if missing:
        raise SystemExit(f"Missing setting(s): {', '.join(missing)}.\n"
                         f"Copy trustguard/.env.example to {ENV_FILE} and fill them in.")
