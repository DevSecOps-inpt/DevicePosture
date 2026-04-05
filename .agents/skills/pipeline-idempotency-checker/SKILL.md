---
name: pipeline-idempotency-checker
description: Use to validate rerun safety, deduplication behavior, and idempotent writes across data pipelines.
---

## Purpose
Prevent data corruption and duplicate side effects by validating idempotency guarantees for retries and backfills.

## When to Use
- Introducing retries/backfills/reprocessing.
- Changing sink semantics or checkpointing.
- Investigating duplicate records after failures.

## When Not to Use
- Immutable read-only analysis with no writes.
- Tasks unrelated to rerun/retry safety.

## Required Inputs
- Write patterns (append/upsert/merge/overwrite).
- Primary keys or dedupe strategy.
- Retry/checkpoint behavior.

## Step-by-Step Workflow
1. Identify all write side effects and sink semantics.
2. Validate deterministic keys and dedupe windows.
3. Check checkpoint/offset handling and replay boundaries.
4. Test rerun scenarios (same window, partial failure, full replay).
5. Document failure modes and required guards.

## Expected Outputs
- Idempotency risk matrix.
- Concrete hardening actions for rerun safety.
- Test scenarios and acceptance criteria.

## Failure and Edge-Case Handling
- If keys are missing, mark as high risk and propose deterministic key strategy.
- If external side effects exist, require compensating-action design.
- If replay boundaries are unknown, mark verification as incomplete.

