---
name: security-best-practices
description: Use for practical application-security reviews and hardening actions with explicit risk, impact, and fixes.
---

## Purpose
Provide repeatable secure-coding and architecture checks for backend, frontend, and integration code.

## When to Use
- Reviewing code for security risks.
- Designing auth/session/RBAC flows.
- Assessing external integration safety and failure behavior.

## When Not to Use
- Pure UI styling work with no security impact.
- Tasks that only require formatting or copy edits.

## Required Inputs
- Target files/routes/endpoints.
- Threat surface and trust boundaries.
- Existing auth/session model.

## Step-by-Step Workflow
1. Enumerate attack surfaces and privileged actions.
2. Check OWASP-relevant controls (validation, authz, session, leakage).
3. Identify exploit path and production impact for each issue.
4. Propose minimal safe fix and verification checks.
5. Capture residual risks and follow-up items.

## Expected Outputs
- Prioritized findings with severity and concrete remediation.
- Verification steps for each remediation.
- Clear residual-risk statement.

## Failure and Edge-Case Handling
- If runtime verification is blocked, mark findings as static-analysis only.
- If code context is partial, list assumptions explicitly.
- If no significant issue is found, state that and list remaining blind spots.

