---
name: spark-performance-auditor
description: Use for Spark workload performance diagnostics, tuning guidance, and cost-latency tradeoff review.
---

## Purpose
Improve Spark job efficiency through practical tuning checks and evidence-based recommendations.

## When to Use
- Slow or expensive Spark jobs.
- Shuffle-heavy stages or skew symptoms.
- Cluster sizing and executor tuning decisions.

## When Not to Use
- Non-Spark workloads.
- Tasks without performance objectives or telemetry.

## Required Inputs
- Spark job configs and stage metrics.
- Data sizes/partitioning patterns.
- Current SLAs and resource limits.

## Step-by-Step Workflow
1. Baseline execution metrics and bottleneck stages.
2. Check partitioning, skew, shuffle, and broadcast opportunities.
3. Review memory/executor/core settings and serialization.
4. Propose minimal tuning changes with expected impact.
5. Define before/after measurement plan.

## Expected Outputs
- Tuning recommendations prioritized by impact and risk.
- Measurement checklist for regression-safe validation.

## Failure and Edge-Case Handling
- If metrics are incomplete, provide bounded hypotheses and required telemetry.
- If workload is highly variable, recommend percentile-based validation.
- If cluster constraints are fixed, prioritize query/data-layout optimizations.

