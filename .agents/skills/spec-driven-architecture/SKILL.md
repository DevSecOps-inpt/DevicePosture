---
name: spec-driven-architecture
description: Use Spec-Kit-inspired templates only for high-level architecture and high-level specification, never for granular task tracking.
---

## Purpose
Enable high-quality architecture/spec drafting while preserving Beads as the sole granular execution tracker.

## When to Use
- Defining system principles and architecture boundaries.
- Writing high-level specifications before implementation.
- Aligning stakeholders on scope and outcomes.

## When Not to Use
- Breaking work into granular execution tasks.
- Tracking day-to-day implementation steps (use Beads).

## Required Inputs
- Problem statement and scope.
- Constraints and non-goals.
- High-level architecture context.

## Step-by-Step Workflow
1. Choose the correct template from `docs/agent-playbook/specs/`.
2. Draft principles via `speckit.constitution` wrapper prompt.
3. Draft high-level specification via `speckit.specify` wrapper prompt.
4. Convert executable implementation items into Beads issues.
5. Keep specs free from granular checklist execution tracking.

## Expected Outputs
- High-level constitution and specification artifacts.
- Clear boundaries and acceptance criteria.
- Linked Beads issues for execution work.

## Failure and Edge-Case Handling
- If details become granular, move them into Beads and trim the spec.
- If scope is unclear, document assumptions and unresolved decisions.
- If templates are unavailable, recreate using local structure and continue.

