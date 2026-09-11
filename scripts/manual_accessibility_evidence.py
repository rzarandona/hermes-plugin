from __future__ import annotations

import json

from hermes_kanban_workflow.reporting.technical_packet import (
    ACCESSIBILITY_SURFACES,
    SUPPORTED_ENVIRONMENT,
)


def main() -> None:
    """Print a blank manual checklist; never synthesize AT evidence."""
    report = {
        "status": "UNEXECUTED",
        "release_ready": False,
        "claim": "No assistive-technology evidence was executed or observed by this script.",
        "supported_environment": {
            "agent": SUPPORTED_ENVIRONMENT.agent_version,
            "desktop": SUPPORTED_ENVIRONMENT.desktop_version,
            "source_commit": SUPPORTED_ENVIRONMENT.source_commit,
            "python": ">=3.11,<3.14",
            "manifest": SUPPORTED_ENVIRONMENT.manifest_version,
            "api_generation": SUPPORTED_ENVIRONMENT.api_generation,
            "windows": SUPPORTED_ENVIRONMENT.windows_version,
            "windows_build": SUPPORTED_ENVIRONMENT.windows_build,
            "terminal": SUPPORTED_ENVIRONMENT.terminal_version,
            "powershell": SUPPORTED_ENVIRONMENT.powershell_version,
            "edge": SUPPORTED_ENVIRONMENT.edge_version,
            "chrome": SUPPORTED_ENVIRONMENT.chrome_version,
            "narrator": SUPPORTED_ENVIRONMENT.narrator_build,
            "nvda": SUPPORTED_ENVIRONMENT.nvda_version,
        },
        "surfaces": [
            {"surface": surface.surface, "status": "UNEXECUTED", "notes": ""}
            for surface in ACCESSIBILITY_SURFACES
        ],
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
