"""Profile-local switch and read-only board observation; never enforcement."""
from __future__ import annotations

import importlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Any

OBSERVE_SOURCE_COMMIT = "08165d58931841cee713468ae89032af7c57060a"
_STATUSES = frozenset({"triage", "todo", "ready", "running", "blocked", "review", "done", "archived"})


def host_source(root: Path) -> str:
    """Read source identity without bootstrapping, updating, or repairing Hermes."""
    if not (3, 11) <= sys.version_info[:2] < (3, 14):
        return "unsupported-python"
    try:
        identity = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=3, check=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).stdout.strip()
        changes = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain=v1", "-uno"],
            capture_output=True, text=True, timeout=3, check=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return identity if not changes else "dirty-source"


class Observer:
    def __init__(self, home: Path, board: Path, source: str | Callable[[], str]) -> None:
        self.home = home.resolve()
        self.board = board.resolve()
        self.host_source = source
        self.state_path = self.home / "state" / "hermes-kanban-workflow-observe.json"

    def compatible(self) -> bool:
        identity = self.host_source() if callable(self.host_source) else self.host_source
        return identity == OBSERVE_SOURCE_COMMIT

    def requested_enabled(self) -> bool:
        try:
            if self.state_path.stat().st_size > 4096:
                return False
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return (isinstance(value, dict) and type(value.get("schema")) is int
                and value.get("schema") == 1 and value.get("enabled") is True)

    def set_enabled(self, enabled: bool) -> None:
        if type(enabled) is not bool:
            raise ValueError("SWITCH_REQUIRES_BOOLEAN")
        if enabled and not self.compatible():
            raise PermissionError("OBSERVE_HOST_UNSUPPORTED")
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary: Path | None = None
        try:
            with NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.state_path.parent, delete=False,
                prefix=".kanban-switch-", suffix=".json",
            ) as stream:
                temporary = Path(stream.name)
                json.dump({"schema": 1, "enabled": enabled}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.state_path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def _board_summary(self) -> dict[str, object]:
        if not self.board.is_file():
            return {"available": False, "code": "BOARD_NOT_INITIALIZED"}
        try:
            # SQLite's read-only WAL connections can still write source SHM files.
            # Copy a stable DB/WAL pair using filesystem reads and open only the copy.
            with TemporaryDirectory(prefix="hermes-kanban-observe-") as directory:
                snapshot = Path(directory) / "kanban.db"
                wal = self.board.with_name(self.board.name + "-wal")
                sources = (self.board, wal, self.board.with_name(self.board.name + "-journal"))

                def fingerprint() -> list[tuple[int, int, int, int] | None]:
                    result: list[tuple[int, int, int, int] | None] = []
                    for path in sources:
                        try:
                            stat = path.stat()
                            result.append((stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns))
                        except FileNotFoundError:
                            result.append(None)
                    return result

                for _ in range(3):
                    before = fingerprint()
                    if before[2] is not None:
                        return {"available": False, "code": "BOARD_BUSY"}
                    shutil.copyfile(self.board, snapshot)
                    snapshot_wal = snapshot.with_name(snapshot.name + "-wal")
                    if before[1] is not None:
                        shutil.copyfile(wal, snapshot_wal)
                    else:
                        snapshot_wal.unlink(missing_ok=True)
                    if before == fingerprint():
                        break
                else:
                    return {"available": False, "code": "BOARD_BUSY"}
                with closing(sqlite3.connect(snapshot.as_uri() + "?mode=ro", uri=True, timeout=1)) as db:
                    db.execute("PRAGMA query_only=ON")
                    rows = db.execute("SELECT status, COUNT(*) FROM tasks GROUP BY status").fetchall()
            counts: dict[str, int] = {}
            for status, count in rows:
                label = status if status in _STATUSES else "unknown"
                counts[label] = counts.get(label, 0) + count
            return {"available": True, "counts": counts, "total": sum(counts.values())}
        except (sqlite3.Error, OSError):
            return {"available": False, "code": "BOARD_READ_FAILED"}

    def status(self) -> dict[str, object]:
        requested = self.requested_enabled()
        compatible = self.compatible()
        enabled = requested and compatible
        return {
            "enabled": enabled, "requested_enabled": requested,
            "mode": "observe-only" if enabled else "unavailable" if requested else "off",
            "compatible": compatible, "enforcement": "disabled",
            "task_execution": "disabled", "asana_writes": "disabled",
            "production_deployment": "disabled",
            "board": self._board_summary() if enabled else None,
        }


def runtime_observer() -> Observer:
    constants = importlib.import_module("hermes_constants")
    plugins = importlib.import_module("hermes_cli.plugins")
    kanban = importlib.import_module("hermes_cli.kanban_db")
    root = Path(str(plugins.__file__)).resolve().parents[1]
    return Observer(constants.get_hermes_home(), kanban.kanban_db_path(),
                    lambda: host_source(root))


def register(ctx: Any, observer: Observer | None = None) -> None:
    """Register only a read tool and a human-operated switch command."""
    observer = observer or runtime_observer()

    def tool(args: dict[str, object], **kwargs: object) -> str:
        if args:
            return json.dumps({"error": "NO_ARGUMENTS_ACCEPTED"})
        return json.dumps(observer.status(), sort_keys=True)

    def command(raw_args: str = "", **kwargs: object) -> str:
        choice = raw_args.strip().lower()
        if choice in {"on", "off"}:
            try:
                observer.set_enabled(choice == "on")
            except (OSError, ValueError, PermissionError) as exc:
                return f"Switch unchanged: {exc}"
        elif choice not in {"", "status"}:
            return "Use /kanban_workflow on, off, or status."
        status = observer.status()
        label = "ON (status only)" if status["enabled"] else "OFF"
        return f"Rein Hermes Kanban Plugin: {label}. Task execution and enforcement are disabled."

    ctx.register_tool(
        name="kanban_status", toolset="kanban-workflow",
        schema={"name": "kanban_status", "description": "Read plugin switch and Kanban status counts only.",
                "parameters": {"type": "object", "properties": {}, "additionalProperties": False}},
        handler=tool, description="Read plugin switch and board counts. No task writes or execution.",
    )
    ctx.register_command(
        name="kanban_workflow", handler=command, args_hint="on|off|status",
        description="Enable or disable status-only observation for this profile.",
    )
