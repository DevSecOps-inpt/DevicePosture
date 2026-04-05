# Prompt Generator Adaptation Record

- Source URL: `https://github.com/huangserva/skill-prompt-generator`
- Access date: `2026-04-03`
- Retrieval reference: `HEAD 5e0a54271ebf35a59cc61d9427576dbee1454382`

## Commands run
- `git ls-remote https://github.com/huangserva/skill-prompt-generator.git HEAD`
- `Invoke-RestMethod https://api.github.com/repos/huangserva/skill-prompt-generator/contents`
- `curl -L https://raw.githubusercontent.com/huangserva/skill-prompt-generator/5e0a54271ebf35a59cc61d9427576dbee1454382/README.md`

## Adopted components
- Local skill-authoring workflow concept.
- Lightweight generator utility implemented at:
  - `tools/skill-prompt-generator/generate_skill_skeleton.py`
  - `tools/skill-prompt-generator/README.md`
- Local skill wrapper:
  - `.agents/skills/prompt-generator/SKILL.md`

## Skipped components
- Full upstream project mirroring.
- Upstream global/agent-specific runtime assumptions.
- Non-essential frameworks and large content bundles.

## Adaptation notes
- Implementation is intentionally minimal and repo-local.
- Output format enforces this repository’s SKILL front matter/section policy.

## Provenance and license notes
- Source is public on GitHub.
- No full-code vendoring performed; only minimal local tooling was created.

