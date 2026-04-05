# OpenAI Skills Baseline Installation Record

- Source URL: `https://github.com/openai/skills`
- Access date: `2026-04-03`
- Retrieval reference: `HEAD 736f600bf6ecbc000c04f1d2710b990899f28903`

## Commands run
- `git ls-remote https://github.com/openai/skills.git HEAD`
- `Invoke-RestMethod https://api.github.com/repos/openai/skills/contents`
- `Invoke-RestMethod https://api.github.com/repos/openai/skills/contents/skills/.curated`
- `curl -L https://raw.githubusercontent.com/openai/skills/736f600bf6ecbc000c04f1d2710b990899f28903/skills/.curated/doc/SKILL.md`

## Installed baseline skills (repo-local)
- `openai-docs` -> `.agents/skills/openai-docs/SKILL.md`
- `security-best-practices` -> `.agents/skills/security-best-practices/SKILL.md`
- `doc` -> `.agents/skills/doc/SKILL.md`

## What was adopted
- Local-first skill entries for OpenAI docs, security review, and documentation workflow.
- Structure aligned to repository-required SKILL format.

## What was skipped
- Full upstream catalog mirroring.
- Demo or unrelated skills (for example deployment/provider-specific skills not required for local bootstrap).
- Global/home-directory install patterns.

## Selection rationale
- `openai-docs`: needed for source-backed OpenAI API/product guidance.
- `security-best-practices`: needed for recurring security review hardening.
- `doc`: needed for repeatable operational and technical documentation.

## Provenance and license notes
- Upstream repository is public on GitHub.
- No full vendoring performed; only adapted local skill guidance was created.

