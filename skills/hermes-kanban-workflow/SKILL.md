---
name: hermes-kanban-workflow
description: "Advise on Hermes Kanban package gates; never mutate state."
version: 0.1.0
metadata:
  hermes:
    tags: [kanban, workflow, advisory, fail-closed]
---

# Hermes Kanban Workflow Advisory

Use this skill to explain package status, the four lifecycle API names, required evidence, typed denials, role duties, recovery routes, and exact Owner stage decisions.

## Hard boundary

This skill is advisory only. It must never install or activate the plugin, register an enforcement surface, write workflow/ledger/product state, provision secrets, create review/Owner authority, call an effect adapter, modify a Hermes profile, or convert repository rehearsal evidence into external proof.

## Guidance order

1. Read `release/evidence-locators.json` and preserve every BLOCKED/UNSUPPORTED state.
2. Use `status` or `preflight-info` only when inspection is requested.
3. Name the exact stage, predecessor, package/policy/host/version, evidence, reviewer, Owner decision, denial, kill, and rollback contract.
4. On ambiguity or unknown external effect, fail closed and route to the named accountable owner.
5. Remind the operator that build/test success leaves installation and activation unauthorized.
