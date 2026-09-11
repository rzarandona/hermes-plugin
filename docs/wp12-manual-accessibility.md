# WP12 manual accessibility evidence boundary

This repository supplies **automated contracts only**. No Narrator, NVDA, browser, terminal,
focus, notification, artifact-open, or Explorer evidence has been executed. Until an authorized
operator runs the exact supported matrix, status is `UNEXECUTED`, not PASS, and affected surface
release readiness remains blocked.

Generate the bounded blank record with:

```text
.venv/Scripts/python.exe scripts/manual_accessibility_evidence.py
```

The script cannot record PASS and cannot claim actual assistive-technology observation. It emits
only an `UNEXECUTED` checklist for these plugin-owned surfaces:

1. Hermes owner questions
2. Kanban cards and status details
3. reviewer/QA forms
4. owner briefs
5. artifact-locator actions
6. operator CLI output
7. packaged teaching/reference HTML

For each surface, an authorized manual procedure must separately observe semantic names, roles and
states; keyboard order and Enter/Space activation; visible focus; status announcements; non-color
meaning; 200% zoom; 390-pixel layout; table containment; contrast tokens; and reduced motion.
Missing screen-reader, focus, open-artifact, Explorer, or notification capability is
`ACCESSIBILITY_CAPABILITY_UNSUPPORTED`, requires the documented semantic-text/keyboard/manual
route, and blocks release readiness.

## Exact supported matrix

Hermes Agent 0.20.5; Desktop 0.17.0; source
`a251e87d826f4ef7c75a8927d5304e24cf43ef54`; Python >=3.11,<3.14; manifest v2;
API generation 1; Windows 11 24H2 build 26100; Windows Terminal 1.22; PowerShell 7.5;
Edge 140; Chrome 140; Narrator build 26100; NVDA 2025.1. Every unlisted environment is
`ENVIRONMENT_UNSUPPORTED`.

## Artifact manual route

When host action support is absent or cannot be verified, report
`ARTIFACT_LOCATOR_UNSUPPORTED`. Preserve the exact deliverable identity, human label, and canonical
locator in the OwnerBrief. The manual route is: open File Explorer and navigate to the exact
canonical locator. Do not report an automatic-open success.
