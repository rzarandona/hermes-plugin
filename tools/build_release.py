"""Build deterministic plugin archive and honest release indexes without installing."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = "hermes-kanban-workflow"
FIXED_TIME = (2026, 8, 29, 0, 0, 0)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_files() -> list[Path]:
    exact = [
        ROOT / "plugin.yaml",
        ROOT / "__init__.py",
        ROOT / "README.md",
        ROOT / "SECURITY.md",
        ROOT / "desktop/plugin.js",
        ROOT / "dashboard/manifest.json",
        ROOT / "dashboard/plugin_api.py",
        ROOT / "skills/hermes-kanban-workflow/SKILL.md",
        ROOT / "release/evidence-locators.json",
        ROOT / "release/audit-verdict.json",
        ROOT / "release/owner-brief.md",
        ROOT / "tests/fixtures/conformance_cases.json",
        ROOT / "tests/fixtures/normative_traceability.json",
        ROOT / "docs/conformance-matrix.md",
    ]
    trees = [ROOT / "src/hermes_kanban_workflow", ROOT / "policies", ROOT / "docs", ROOT / "vendor"]
    values = [path for path in exact if path.exists()]
    for tree in trees:
        values.extend(
            path
            for path in tree.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        )
    return sorted(set(values), key=lambda item: item.relative_to(ROOT).as_posix())


def archive_name(path: Path) -> str:
    relative = path.relative_to(ROOT).as_posix()
    if relative.startswith("src/hermes_kanban_workflow/"):
        relative = relative.removeprefix("src/")
    return f"{PLUGIN}/{relative}"


def write_bundle(output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for path in source_files():
            info = ZipInfo(PurePosixPath(archive_name(path)).as_posix(), FIXED_TIME)
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())


def category(relative: str) -> str:
    if relative.endswith(".whl"):
        return "wheel"
    if relative in {"plugin.yaml", "dashboard/manifest.json"}:
        return "manifest"
    if relative.startswith("policies/") and relative.endswith(".sig"):
        return "signature"
    if relative.startswith("policies/") and "schema" in relative:
        return "schema"
    if relative.startswith("policies/"):
        return "policy"
    if relative.startswith("skills/"):
        return "skill"
    if relative.startswith("docs/") or relative in {"README.md", "SECURITY.md"}:
        return "document"
    if relative.endswith("ledger/schema.py"):
        return "migration"
    if relative.startswith(("tests/", "release/evidence")):
        return "test-evidence-index"
    return "plugin-source"


def write_indexes(bundle: Path) -> None:
    wheel_paths = sorted((ROOT / "dist").glob("*.whl"))
    entries: list[dict[str, object]] = []
    for path in source_files() + wheel_paths + [bundle]:
        relative = path.relative_to(ROOT).as_posix()
        entries.append(
            {
                "path": relative,
                "category": "plugin-bundle" if path == bundle else category(relative),
                "sha256": digest(path),
                "bytes": path.stat().st_size,
            }
        )
    entries.sort(key=lambda item: str(item["path"]))
    inventory = {
        "schema_version": 1,
        "owner": "Build",
        "status": "DEVELOPMENT_NOT_RELEASE_READY",
        "package": PLUGIN,
        "version": "0.1.0",
        "reproducible_timestamp": "2026-08-29T00:00:00Z",
        "installation_authorized": False,
        "activation_authorized": False,
        "entries": entries,
    }
    inventory_path = ROOT / "release/package-inventory.json"
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checks = [
        "# owner: Build",
        "# format: sha256<two spaces>repository-relative-path",
        *[f"{entry['sha256']}  {entry['path']}" for entry in entries],
        f"{digest(inventory_path)}  release/package-inventory.json",
    ]
    header, format_line, *rows = checks
    (ROOT / "release/checksums.txt").write_text(
        "\n".join([header, format_line, *sorted(rows)]) + "\n", encoding="utf-8"
    )


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "dist/hermes-kanban-workflow-plugin.zip")
    parser.add_argument("--verification-root", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    dist_root = (ROOT / "dist").resolve()
    verification_root = args.verification_root.resolve() if args.verification_root else None
    allowed = _within(output, dist_root) or (
        verification_root is not None
        and verification_root != ROOT
        and _within(output, verification_root)
        and not _within(verification_root, ROOT)
    )
    if not allowed:
        parser.error("OUTPUT_MUST_BE_REPO_DIST_OR_EXPLICIT_TEMP_VERIFICATION_ROOT")
    write_bundle(output)
    if _within(output, dist_root):
        write_indexes(output)
    print(json.dumps({"bundle": output.as_posix(), "sha256": digest(output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
