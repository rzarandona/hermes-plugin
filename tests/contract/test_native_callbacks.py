import json
from pathlib import Path

from hermes_kanban_workflow.adapters.hermes_host import HermesPluginContextPort
from tests.contract.test_hermes_adapter import RecordingContext


def test_native_observer_reads_the_hosts_resolved_board_and_captures_profile(tmp_path, monkeypatch):
    import sqlite3
    from types import SimpleNamespace

    from hermes_kanban_workflow import observe

    home = tmp_path / "profile"
    selected = tmp_path / "selected.db"
    with sqlite3.connect(selected) as connection:
        connection.execute("CREATE TABLE tasks(status TEXT)")
        connection.execute("INSERT INTO tasks VALUES ('review')")
    modules = {
        "hermes_constants": SimpleNamespace(
            get_hermes_home=lambda: home, get_default_hermes_root=lambda: tmp_path / "legacy",
        ),
        "hermes_cli.plugins": SimpleNamespace(__file__=str(tmp_path / "host" / "hermes_cli" / "plugins.py")),
        "hermes_cli.kanban_db": SimpleNamespace(kanban_db_path=lambda: selected),
    }
    monkeypatch.setattr(observe.importlib, "import_module", lambda name: modules[name])
    monkeypatch.setattr(observe, "host_source", lambda _: observe.OBSERVE_SOURCE_COMMIT)
    reader = observe.runtime_observer()
    reader.set_enabled(True)
    assert reader.status()["board"] == {"available": True, "counts": {"review": 1}, "total": 1}
    assert reader.home == home.resolve()


def test_tool_callback_accepts_native_arguments_and_rejects_unknown_input(tmp_path: Path):
    from hermes_kanban_workflow.observe import OBSERVE_SOURCE_COMMIT, Observer

    observer = Observer(tmp_path, tmp_path / "absent.db", OBSERVE_SOURCE_COMMIT)
    ctx = RecordingContext()
    HermesPluginContextPort(ctx, observer=observer).register_package_commands()
    schema = ctx.tools[0][1]["schema"]
    assert schema["name"] == "kanban_status"
    assert schema["parameters"]["additionalProperties"] is False
    handler = ctx.tools[0][1]["handler"]
    assert json.loads(handler({}))["mode"] == "off"
    assert json.loads(handler({"execute": True}))["error"] == "NO_ARGUMENTS_ACCEPTED"


def test_native_commands_switch_live_status_and_keep_enforcement_closed(tmp_path: Path):
    from hermes_kanban_workflow.observe import OBSERVE_SOURCE_COMMIT, Observer

    observer = Observer(tmp_path, tmp_path / "absent.db", OBSERVE_SOURCE_COMMIT)
    ctx = RecordingContext()
    HermesPluginContextPort(ctx, observer=observer).register_package_commands()
    commands = dict(ctx.commands)
    assert "ON" in commands["kanban_workflow"]["handler"]("on")
    assert observer.status()["enabled"] is True
    assert "OFF" in commands["kanban_workflow"]["handler"]("off")
    assert observer.status()["enabled"] is False
    assert json.loads(commands["kanban_preflight"]["handler"](""))["enforcement"] == "disabled"
    assert json.loads(commands["kanban_request_activation"]["handler"](""))["code"] == "AUTHENTICATED_SERVICE_ACTIVATION_REQUIRED"
