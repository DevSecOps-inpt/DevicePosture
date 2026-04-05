---
name: software-engineering-refactoring-safety
description: Use for safe refactoring workflows that preserve behavior while reducing complexity and technical debt.
---

## Purpose
Enable behavior-preserving refactors with clear guardrails, staged changes, and measurable safety checks.

## When to Use
- Splitting large modules or classes.
- Replacing duplicated logic with shared abstractions.
- Renaming/restructuring code paths with operational impact.

## When Not to Use
- Urgent hotfixes where structural changes add risk.
- Net-new feature development without refactor scope.

## Required Inputs
- Current implementation and pain points.
- Expected invariant behavior.
- Existing test and observability coverage.

## Step-by-Step Workflow
1. Define invariants that must not change.
2. Add or strengthen characterization tests first.
3. Refactor in small reversible commits.
4. Re-run tests and static checks after each step.
5. Validate logs/metrics for unexpected behavior shifts.
6. Document follow-up debt not solved in this pass.

## Expected Outputs
- Safer code structure with preserved behavior.
- Explicit validation evidence.
- Refactor boundary notes for future contributors.

## Failure and Edge-Case Handling
- If tests are insufficient, stop and add baseline tests before deep refactor.
- If behavior drifts, roll back to last safe checkpoint and narrow scope.
- If refactor becomes feature work, split into separate tracked tasks.

