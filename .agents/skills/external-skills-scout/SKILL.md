---
name: external-skills-scout
description: Use to evaluate external skill ecosystems and distill useful guidance into local repo assets without creating hidden dependencies.
---

## Purpose
Keep the project local-first while still benefiting from external skill ecosystems when explicitly requested.

## When to Use
- Reviewing external skill repositories for potential adoption.
- Updating existing local skills from approved upstream sources.
- Producing provenance records for adopted guidance.

## When Not to Use
- Day-to-day execution where local skills already cover the need.
- Pulling external assets as implicit runtime dependencies.

## Required Inputs
- Target external source URL.
- Adoption objective and scope.
- Existing local skill/doc inventory.

## Step-by-Step Workflow
1. Consult external source only as much as needed.
2. Extract and adapt reusable guidance to local files.
3. Avoid mirroring full upstream repositories by default.
4. Record source URL, date, reference, adopted/skipped items, and notes.
5. Verify local assets are complete and usable without external fetch.

## Expected Outputs
- Local skills/docs with durable guidance.
- Provenance log under `.agents/skills/_meta/`.

## Failure and Edge-Case Handling
- If licensing/provenance is unclear, flag and avoid adoption.
- If source is unavailable, record blocker and continue with local alternatives.
- If guidance conflicts with repo policy, keep repo policy authoritative.

