---
name: doc
description: Use for structured technical documentation creation and maintenance with consistent templates and verification notes.
---

## Purpose
Create and maintain clear technical documentation that remains accurate as the repository evolves.

## When to Use
- Authoring installation/runbooks/playbooks.
- Capturing architecture decisions and operational procedures.
- Updating docs after configuration or tooling changes.

## When Not to Use
- Non-documentation code changes without documentation impact.
- One-off notes that should remain ephemeral.

## Required Inputs
- Target audience and use-case.
- Relevant commands, paths, and expected outcomes.
- Current repository structure.

## Step-by-Step Workflow
1. Identify doc type (setup, operations, reference, troubleshooting).
2. Use existing repo conventions and local templates.
3. Include deterministic commands and verification criteria.
4. Highlight assumptions, prerequisites, and failure paths.
5. Validate referenced paths/commands before finalizing.

## Expected Outputs
- Practical docs with runnable steps.
- Minimal ambiguity in prerequisites and success criteria.
- Maintained consistency with existing repo style.

## Failure and Edge-Case Handling
- If a command is unverified, mark it clearly as unverified.
- If platform behavior differs, provide OS-specific notes.
- If required context is missing, include explicit placeholders and assumptions.

