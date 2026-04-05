---
name: data-engineering-orchestrator
description: Use to coordinate multi-skill data-engineering workflows across pipeline review, Spark tuning, and idempotency hardening.
---

## Purpose
Provide a single orchestration pattern for complex data-engineering changes that require multiple specialized checks.

## When to Use
- End-to-end data platform improvements.
- Multi-component changes touching orchestration, compute, and data correctness.
- Cross-team handoffs requiring structured execution.

## When Not to Use
- Small isolated changes that one specialized skill already covers.
- Work without measurable operational or data-quality outcomes.

## Required Inputs
- Target objective and success metrics.
- Affected jobs/pipelines/services.
- Constraints (latency, cost, correctness, compliance).

## Step-by-Step Workflow
1. Start with `data-pipeline-reviewer` for dependency/coupling map.
2. Run `spark-performance-auditor` for performance/cost hotspots.
3. Run `pipeline-idempotency-checker` for rerun safety.
4. Consolidate findings into phased action plan.
5. Track execution items in Beads and verify outcomes.

## Expected Outputs
- Integrated remediation plan with owners and sequencing.
- Explicit risk/impact tradeoffs across performance and correctness.
- Verification checklist for post-change confidence.

## Failure and Edge-Case Handling
- If one sub-analysis is blocked, continue others and mark dependency.
- If metrics conflict, prioritize correctness and safety, then optimize.
- If verification command is undefined, record that explicitly.

