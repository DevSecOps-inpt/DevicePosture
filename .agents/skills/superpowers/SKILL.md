---
name: superpowers
description: Use for repo-local adaptation of Superpowers-style workflows without global symlinks or home-directory dependencies.
---

## Purpose
Adapt useful Superpowers patterns into repository-local, durable assets that work for this project without relying on user-home installation paths.

## When to Use
- A task needs reusable Codex operating workflows.
- You want to port useful external prompts/processes into this repo.
- Team wants deterministic local behavior across machines.

## When Not to Use
- Global `~/.codex` or `~/.agents` modifications are requested.
- The workflow is one-off and not reusable.

## Required Inputs
- External workflow reference.
- Target local destination paths.
- Constraints from repo-local governance files.

## Step-by-Step Workflow
1. Read external guidance once and extract only reusable ideas.
2. Rewrite guidance into local skills/playbooks under this repo.
3. Avoid symlink/global-home dependencies.
4. Document provenance and adaptation decisions in `_meta`.
5. Verify files exist and are discoverable in repo paths.

## Expected Outputs
- Repo-local skills and prompts implementing adopted workflow ideas.
- Provenance notes with what was adopted and skipped.

## Failure and Edge-Case Handling
- If external source is unavailable, defer adoption and record blocker.
- If external guidance conflicts with repo policy, prioritize repo policy.
- If a pattern requires global state, create a local equivalent instead.

