"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, tuple[float, str, str]] = {}
        self._latest_by_user: dict[str, str] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store a request start time so the response can be paired and timed."""
        key = request_id or f"{user_id}:{len(self._open) + len(self.logs) + 1}"
        started = datetime.now(timezone.utc).timestamp()
        self._open[key] = (started, user_id, text)
        self._latest_by_user[user_id] = key
        return key

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Append a paired request/response record with elapsed milliseconds."""
        key = request_id or self._latest_by_user.get(user_id)
        opened = self._open.pop(key, None) if key else None
        if key and self._latest_by_user.get(user_id) == key:
            self._latest_by_user.pop(user_id, None)
        now = datetime.now(timezone.utc)
        latency_ms = max(0.0, (now.timestamp() - opened[0]) * 1000) if opened else None
        started_at = (
            datetime.fromtimestamp(opened[0], timezone.utc).isoformat()
            if opened
            else None
        )
        self.logs.append(
            {
                "request_id": key,
                "user_id": user_id,
                "started_at": started_at,
                "timestamp": now.isoformat(),
                "input": opened[2] if opened else None,
                "output": text,
                "blocked": bool(blocked),
                "layer": layer,
                "latency_ms": latency_ms,
            }
        )

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
