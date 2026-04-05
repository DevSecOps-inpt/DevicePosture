# Spec Kit Adaptation Record

- Source URL: `https://github.com/github/spec-kit`
- Access date: `2026-04-03`
- Retrieval reference: `HEAD d40c9a6428731678d40c3643ee58ffb8ec09c3e6`

## Commands run
- `git ls-remote https://github.com/github/spec-kit.git HEAD`
- `curl -L https://raw.githubusercontent.com/github/spec-kit/main/README.md`

## What was adopted
- High-level constitution/spec workflow concept.
- Local prompt wrappers:
  - `.codex/prompts/speckit.constitution.md`
  - `.codex/prompts/speckit.specify.md`
- Local templates:
  - `docs/agent-playbook/specs/speckit.constitution.template.md`
  - `docs/agent-playbook/specs/speckit.specification.template.md`
- Local skill:
  - `.agents/skills/spec-driven-architecture/SKILL.md`

## What was intentionally excluded
- CLI installation and full upstream initialization workflow.
- Any use of Spec Kit for granular execution tracking.

## Critical policy enforced
- Spec Kit is for high-level architecture/specification only.
- Granular execution tracking is forbidden in specs and must use Beads.

## Provenance and license notes
- Source is public on GitHub and references a visible LICENSE in upstream repository.
- This repository keeps local adapted guidance only.

