# Known limitations

- Enforcement support is frozen to Windows 11 24H2 x64 build 26100 on NTFS, Hermes Agent 0.20.5, Desktop 0.17.0, and source commit `a251e87d826f4ef7c75a8927d5304e24cf43ef54`.
- The current repository contains the implementation core and contracts, but no installed Windows service, DPAPI-NG broker, production credentials, migration, or activated policy.
- Combined-process enforcement is prohibited; Python module boundaries do not isolate credentials.
- Full accessibility certification requires the exact manual browser, terminal, Narrator, and NVDA matrix on a clean supported host.
- `ARTIFACT_LOCATOR_UNSUPPORTED` is the required fallback when the host cannot reveal an exact artifact.
- Missing development dependencies block the full pytest/Ruff/mypy/Hypothesis suite; the standard-library unit suite remains available.

