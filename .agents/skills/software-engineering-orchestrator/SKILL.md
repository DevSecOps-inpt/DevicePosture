---
name: software-engineering-orchestrator
description: Use to coordinate end-to-end software engineering quality workflows across review, testing, refactoring, and architecture decisions.
---

## Purpose
Provide a structured orchestration path for complex engineering work where quality and maintainability must be managed together.

## When to Use
- Large changes spanning multiple modules.
- Delivery work that includes design, implementation, and hardening.
- Pre-release quality passes for critical areas.

## When Not to Use
- Small single-file fixes that one specialized skill can handle.
- Tasks without engineering quality implications.

## Required Inputs
- Scope, timeline, and risk tolerance.
- Relevant modules and integration points.
- Current quality signals (tests, lint, review history, incidents).

## Step-by-Step Workflow
1. Run architecture-decision framing for major design choices.
2. Apply testing strategy to define confidence gates.
3. Execute implementation/refactor with safety checkpoints.
4. Perform code review against correctness and maintainability.
5. Record follow-up debt and assign tracked execution items.
6. Run final verification and summarize release confidence.

## Expected Outputs
- Cohesive quality plan and execution sequence.
- Clear go/no-go confidence summary.
- Tracked follow-up actions for deferred debt.

## Failure and Edge-Case Handling
- If one analysis path is blocked, continue independent paths and note blockers.
- If quality gates fail, stop rollout and provide minimal remediation plan.
- If verification command is undefined, record that explicitly and avoid guessing.

