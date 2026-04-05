---
name: software-engineering-testing-strategy
description: Use to design pragmatic test plans that balance confidence, speed, and maintenance cost.
---

## Purpose
Create test strategies that are risk-driven, fast to run, and robust against regressions.

## When to Use
- Planning tests for new features.
- Improving flaky or slow test suites.
- Defining release confidence gates.

## When Not to Use
- Tasks with no behavior change.
- Pure infrastructure setup unrelated to testing outcomes.

## Required Inputs
- Change scope and risk profile.
- Existing test pyramid and tooling.
- Runtime constraints (CI time, environments, dependencies).

## Step-by-Step Workflow
1. Classify risk by component and failure impact.
2. Map coverage across unit, integration, and end-to-end layers.
3. Prioritize fast deterministic tests for core logic.
4. Add targeted integration tests for contracts and boundaries.
5. Keep end-to-end tests narrow and high-value.
6. Define pass/fail gates and rollback signals.

## Expected Outputs
- Layered test plan with rationale.
- Minimal required test set for merge confidence.
- Follow-up list for test debt reduction.

## Failure and Edge-Case Handling
- If CI environment is unstable, isolate flaky tests and mark non-blocking where appropriate.
- If external dependencies are unavailable, use contract tests and explicit assumptions.
- If time is constrained, prioritize highest-impact risk cases first.

