---
name: openai-docs
description: Use for OpenAI platform/API questions that require official-doc guidance with repo-local execution defaults.
---

## Purpose
Provide a stable, repo-local workflow for answering OpenAI product/API questions using official docs first, then convert outcomes into durable local artifacts when needed.

## When to Use
- A task asks how to use OpenAI APIs, models, auth, or SDK behavior.
- The team needs source-backed guidance for model selection or migration.
- A repository change depends on OpenAI docs decisions.

## When Not to Use
- The task is unrelated to OpenAI products.
- The answer is fully contained in existing repo docs.

## Required Inputs
- User question or change request.
- Current repository context and impacted files.
- Any explicit version/model constraints.

## Step-by-Step Workflow
1. Read relevant local docs first (`README`, playbooks, existing skills).
2. Consult official OpenAI documentation as the primary source.
3. Extract only needed facts and decisions.
4. Propose or apply repo-local updates for durable reuse (skills/docs/config).
5. Record links and concise rationale in the output.

## Expected Outputs
- A concise answer grounded in official docs.
- Repo-local updates when recurring guidance is identified.
- Explicit assumptions and known unknowns.

## Failure and Edge-Case Handling
- If docs are ambiguous, state uncertainty and provide safe fallback guidance.
- If network access is unavailable, provide best-effort local guidance and mark as unverified.
- If versions conflict, call out the conflict and recommend a pinned decision.

