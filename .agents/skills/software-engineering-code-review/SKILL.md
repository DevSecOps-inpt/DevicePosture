---
name: software-engineering-code-review
description: Use for disciplined code reviews focused on correctness, maintainability, clarity, and regression risk.
---

## Purpose
Provide a repeatable code-review workflow that catches defects early and improves long-term maintainability.

## When to Use
- Reviewing feature changes before merge.
- Auditing risky refactors or bug fixes.
- Evaluating pull requests with cross-module impact.

## When Not to Use
- Pure brainstorming with no code artifacts.
- Trivial formatting-only edits with zero behavior impact.

## Required Inputs
- Changed files or pull request diff.
- Relevant requirements and acceptance criteria.
- Test results (if available).

## Step-by-Step Workflow
1. Read change intent and expected behavior first.
2. Review correctness and edge-case handling.
3. Review maintainability (naming, cohesion, duplication, complexity).
4. Review safety (error handling, logging, input validation, authz where relevant).
5. Verify test coverage for happy path, edge cases, and regressions.
6. Summarize findings by severity and provide actionable fixes.

## Expected Outputs
- Prioritized findings with clear rationale.
- Specific remediation suggestions.
- Residual risk statement when verification is incomplete.

## Failure and Edge-Case Handling
- If requirements are unclear, list assumptions and mark confidence.
- If tests are missing, explicitly flag verification gaps.
- If context is partial, classify findings as best-effort and request missing artifacts.

