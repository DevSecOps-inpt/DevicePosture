---
name: workflow-orchestrator
description: Use for end-of-session orchestration with the Land-the-Plane protocol and explicit verification status.
---

## Purpose
Ensure ephemeral sessions end in a controlled, traceable state with task tracking, follow-up capture, and verification clarity.

## When to Use
- Before ending a development session.
- After completing a major task batch.
- When handing off work to another operator.

## When Not to Use
- During early exploration before work ownership is clear.
- As a replacement for Beads lifecycle operations.

## Required Inputs
- Current task ids and outcomes.
- Discovered technical debt or follow-up items.
- Current verification/build/test status.

## Step-by-Step Workflow
1. Update current Beads issue with findings or close it if complete.
2. File Beads issues for newly discovered follow-up work.
3. Run repository’s obvious verification/build command if defined.
4. Confirm repository is not knowingly left broken.
5. If verification is undefined, explicitly record that instead of guessing.

## Expected Outputs
- Cleanly updated/closed Beads records.
- Captured follow-up tasks with dependencies.
- Explicit verification statement.

## Failure and Edge-Case Handling
- If Beads is unavailable, record exact failure and use host-wrapper path when applicable.
- If verification fails, do not hide it; include failure context and next action.
- If no verification command exists, mark as undefined.

