---
name: software-engineering-architecture-decisions
description: Use to evaluate and document architecture decisions with clear tradeoffs, constraints, and migration paths.
---

## Purpose
Guide architecture decisions so they remain explainable, auditable, and aligned with product and operational constraints.

## When to Use
- Choosing between multiple technical designs.
- Introducing new services, frameworks, or integration boundaries.
- Planning significant dependency or data-model changes.

## When Not to Use
- Small isolated code changes with no architectural effect.
- Temporary experiments with no production path.

## Required Inputs
- Problem statement and non-goals.
- Constraints (scale, security, reliability, team capacity).
- Candidate options with known tradeoffs.

## Step-by-Step Workflow
1. Define decision scope and success criteria.
2. Enumerate viable options and discard weak ones with reasons.
3. Compare options across complexity, cost, risk, and operability.
4. Select a recommendation and define migration strategy.
5. Identify measurable checkpoints for validation.
6. Record decision context and revisit triggers.

## Expected Outputs
- Clear recommended architecture direction.
- Explicit tradeoff matrix and assumptions.
- Migration/rollback considerations.

## Failure and Edge-Case Handling
- If data is insufficient, make assumptions explicit and limit recommendation confidence.
- If options are close, prefer lower operational complexity and reversible paths.
- If constraints conflict, escalate with decision criteria and unresolved questions.

