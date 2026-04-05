---
name: beads-workflow
description: Use for strict Beads task execution using ready/claim/create/close commands with safety checks and host-wrapper fallback.
---

## Purpose
Standardize granular execution tracking with Beads while preserving datastore safety and clear host-boundary handling.

## When to Use
- Starting or updating granular implementation tasks.
- Capturing discovered follow-up work.
- Closing completed execution items.

## When Not to Use
- High-level architecture drafting (use specs instead).
- Creating markdown task trackers for granular work.

## Required Inputs
- Current repository path.
- Parent issue/task id (when creating discovered work).
- Explicit task completion evidence.

## Step-by-Step Workflow
1. Discover unblocked work: `bd ready --json`.
2. Claim selected task: `bd update <id> --claim`.
3. Create discovered work from parent: `bd create "Task Name" --deps discovered-from:<parent_id>`.
4. Complete task: `bd close <id> --reason "Completed"`.
5. If sandbox cannot reach required host daemon/localhost, rerun via `./tools/host/beads-host ...` and label result as host-executed.

## Expected Outputs
- Up-to-date Beads ownership and status.
- Discovered dependency graph maintained with `discovered-from`.
- Closed tasks include explicit completion reason.

## Failure and Edge-Case Handling
- Never run `bd init --force` automatically.
- Never delete `.beads/dolt` or do blind recovery by default.
- If Beads is unavailable, record exact command/error and install method attempts.
- `bd --version` alone is insufficient; require a real Beads operation.

