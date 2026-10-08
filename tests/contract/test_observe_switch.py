"""Catch unsafe enabled defaults, stale switches, and writes during observation."""
from __future__ import annotations

import importlib
import json
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest


def observer(tmp_path: Path):
    # Import inside the test so missing implementation is an explicit assertion failure.
    assert importlib.util.find_spec("hermes_kanban_workflow.observe") is not None
    module = importlib.import_module("hermes_kanban_workflow.observe")
    db = tmp_path / "kanban.db"
    with closing(sqlite3.connect(db)) as connection:
        connection.execute("CREATE TABLE tasks(id TEXT PRIMARY KEY, status TEXT NOT NULL)")
        connection.executemany("INSERT INTO tasks VALUES (?, ?)", [("a", "todo"), ("b", "blocked")])
        connection.commit()
    return module.Observer(tmp_path / "profile", db, module.OBSERVE_SOURCE_COMMIT)


def test_missing_switch_stays_off_and_does_not_read_board(tmp_path: Path) -> None:
    instance = observer(tmp_path)
    instance.board.unlink()
    result = instance.status()
    assert result["enabled"] is False
    assert result["mode"] == "off"
    assert result["enforcement"] == "disabled"
    assert result["board"] is None


def test_switch_is_durable_and_off_takes_effect_in_existing_reader(tmp_path: Path) -> None:
    instance = observer(tmp_path)
    original_bytes = instance.board.read_bytes()
    instance.set_enabled(True)
    assert instance.status()["board"]["counts"] == {"blocked": 1, "todo": 1}
    another_reader = type(instance)(instance.home, instance.board, instance.host_source)
    assert another_reader.status()["enabled"] is True
    another_reader.set_enabled(False)
    assert instance.status()["enabled"] is False
    assert instance.status()["board"] is None
    assert instance.board.read_bytes() == original_bytes


@pytest.mark.parametrize("contents", ["broken", '[]', '{"enabled":"true"}', '{"schema":2,"enabled":true}',
                                    '{"schema":true,"enabled":true}', '{"schema":1.0,"enabled":true}'])
def test_bad_switch_data_cannot_enable_observation(tmp_path: Path, contents: str) -> None:
    instance = observer(tmp_path)
    instance.state_path.parent.mkdir(parents=True)
    instance.state_path.write_text(contents)
    assert instance.status()["enabled"] is False
    assert instance.status()["board"] is None


def test_unverified_host_cannot_enable_and_off_is_always_available(tmp_path: Path) -> None:
    instance = observer(tmp_path)
    instance.set_enabled(True)
    instance.host_source = "different-source"
    with pytest.raises(PermissionError, match="OBSERVE_HOST_UNSUPPORTED"):
        instance.set_enabled(True)
    assert instance.status()["mode"] == "unavailable"
    assert instance.status()["board"] is None
    instance.set_enabled(False)
    assert instance.status()["enabled"] is False


def test_profile_switch_does_not_change_another_profile(tmp_path: Path) -> None:
    first = observer(tmp_path)
    second = type(first)(tmp_path / "another", first.board, first.host_source)
    first.set_enabled(True)
    assert second.status()["enabled"] is False
    assert json.loads(first.state_path.read_text())["enabled"] is True


def test_missing_board_is_reported_without_creating_it(tmp_path: Path) -> None:
    instance = observer(tmp_path)
    instance.set_enabled(True)
    instance.board.unlink()
    result = instance.status()
    assert result["board"]["available"] is False
    assert not instance.board.exists()


def test_corrupt_board_is_not_reported_as_empty_success(tmp_path: Path) -> None:
    instance = observer(tmp_path)
    instance.set_enabled(True)
    instance.board.write_bytes(b"not a database")
    assert instance.status()["board"]["available"] is False
    assert instance.status()["board"]["code"] == "BOARD_READ_FAILED"


def test_control_cli_shows_off_without_loading_or_updating_hermes(tmp_path: Path) -> None:
    script = Path("tools/observe_control.py")
    assert script.is_file(), "The user needs an executable switch controller."
    profile = tmp_path / "profile"
    result = subprocess.run(
        [sys.executable, str(script), "status", "--profile-home", str(profile),
         "--hermes-root", str(tmp_path / "absent-host")],
        capture_output=True, text=True, check=True,
    )
    payload = json.loads(result.stdout)
    assert payload["enabled"] is False
    assert payload["enforcement"] == "disabled"
    assert not profile.exists()


def test_closed_wal_board_observation_does_not_create_source_sidecars(tmp_path: Path) -> None:
    instance = observer(tmp_path)
    with closing(sqlite3.connect(instance.board)) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
    instance.set_enabled(True)
    before = {path.name: path.read_bytes() for path in tmp_path.glob("kanban.db*")}
    assert instance.status()["board"]["total"] == 2
    assert {path.name: path.read_bytes() for path in tmp_path.glob("kanban.db*")} == before


def test_live_wal_commits_are_visible_without_touching_source_files(tmp_path: Path) -> None:
    instance = observer(tmp_path)
    instance.set_enabled(True)
    with closing(sqlite3.connect(instance.board)) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("INSERT INTO tasks VALUES ('c', 'review')")
        connection.commit()
        before = {path.name: path.read_bytes() for path in tmp_path.glob("kanban.db*")}
        assert instance.status()["board"]["counts"] == {"blocked": 1, "review": 1, "todo": 1}
        assert {path.name: path.read_bytes() for path in tmp_path.glob("kanban.db*")} == before


def test_unstable_snapshot_is_unavailable_instead_of_stale_success(tmp_path: Path, monkeypatch) -> None:
    instance = observer(tmp_path)
    instance.set_enabled(True)
    module = importlib.import_module("hermes_kanban_workflow.observe")
    original_copy = module.shutil.copyfile
    calls = []

    def copy_and_change(source, target):
        original_copy(source, target)
        calls.append(target)
        with source.open("ab") as stream:
            stream.write(b"changed")

    monkeypatch.setattr(module.shutil, "copyfile", copy_and_change)
    assert instance.status()["board"] == {"available": False, "code": "BOARD_BUSY"}
    assert len(calls) == 3


def test_rollback_journal_prevents_snapshot_success(tmp_path: Path) -> None:
    instance = observer(tmp_path)
    instance.set_enabled(True)
    instance.board.with_name("kanban.db-journal").write_bytes(b"pending")
    assert instance.status()["board"] == {"available": False, "code": "BOARD_BUSY"}
