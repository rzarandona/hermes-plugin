"""Local user switch for the status-only pilot. No Hermes bootstrap or gateway restart."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src" if (PLUGIN_ROOT / "src").is_dir() else PLUGIN_ROOT))

from hermes_kanban_workflow.observe import Observer, host_source


def show_window(observer: Observer) -> None:
    import tkinter as tk
    from tkinter import messagebox

    window = tk.Tk()
    window.title("Rein Hermes Kanban Plugin")
    window.geometry("440x330")
    window.resizable(False, False)
    window.configure(bg="#f5f6f8")
    tk.Label(window, text="Rein Hermes Kanban", font=("Segoe UI", 20, "bold"),
             bg="#f5f6f8", fg="#18212f").pack(pady=(24, 4))
    tk.Label(window, text="Status-only plugin", font=("Segoe UI", 11),
             bg="#f5f6f8", fg="#596574").pack()
    label = tk.Label(window, font=("Segoe UI", 15, "bold"), bg="#f5f6f8")
    label.pack(pady=(20, 8))
    detail = tk.Label(window, font=("Segoe UI", 10), bg="#f5f6f8", fg="#596574", wraplength=390)
    detail.pack()

    def refresh() -> None:
        state = observer.status()
        active = state["enabled"]
        label.configure(text="Enabled" if active else "Disabled", fg="#18774a" if active else "#596574")
        board = state["board"]
        if isinstance(board, dict) and board.get("available"):
            text = f"Board visible · {board['total']} cards"
        elif active:
            text = "Enabled · board currently unavailable"
        elif not state["compatible"]:
            text = "Host compatibility check required before enabling"
        else:
            text = "Board observation is paused"
        detail.configure(text=text)

    def change(value: bool) -> None:
        try:
            observer.set_enabled(value)
        except (OSError, ValueError, PermissionError) as exc:
            messagebox.showerror("Switch unchanged", str(exc), parent=window)
        refresh()

    buttons = tk.Frame(window, bg="#f5f6f8")
    buttons.pack(pady=18)
    tk.Button(buttons, text="Enable", width=13, font=("Segoe UI", 11), bg="#ed8b1c", fg="#ffffff",
              relief="flat", command=lambda: change(True)).pack(side="left", padx=6)
    tk.Button(buttons, text="Disable", width=13, font=("Segoe UI", 11), bg="#e1e5eb", fg="#18212f",
              relief="flat", command=lambda: change(False)).pack(side="left", padx=6)
    tk.Label(window, text="This switch controls observation only.\nIt does not start workers or deploy website changes.",
             font=("Segoe UI", 10), bg="#f5f6f8", fg="#596574").pack()
    refresh()
    window.mainloop()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("on", "off", "status", "window"))
    parser.add_argument("--profile-home", type=Path, required=True)
    parser.add_argument("--hermes-root", type=Path, required=True)
    parser.add_argument("--board", type=Path)
    args = parser.parse_args()
    observer = Observer(
        args.profile_home, args.board or args.hermes_root.parent / "kanban.db",
        lambda: host_source(args.hermes_root),
    )
    if args.command == "window":
        show_window(observer)
        return 0
    try:
        if args.command in {"on", "off"}:
            observer.set_enabled(args.command == "on")
        print(json.dumps(observer.status(), sort_keys=True))
        return 0
    except (OSError, ValueError, PermissionError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
