# Superpowers Adaptation Record

- Source URL: `https://raw.githubusercontent.com/obra/superpowers/refs/heads/main/.codex/INSTALL.md`
- Access date: `2026-04-03`
- Retrieval reference: `obra/superpowers HEAD b7a8f76985f1e93e75dd2f2a3b424dc731bd9d37`

## Commands run
- `git ls-remote https://github.com/obra/superpowers.git HEAD`
- `curl -L https://raw.githubusercontent.com/obra/superpowers/refs/heads/main/.codex/INSTALL.md`

## What was adopted
- The idea of reusable skill-driven workflow packaging.
- Verification mindset for installation/discovery.
- Local adaptation via `.agents/skills/superpowers/SKILL.md`.

## What was intentionally not adopted
- Global `~/.codex` clone path.
- Global `~/.agents/skills` symlink/junction requirement.
- Any user-home dependency for normal repo execution.

## Adaptation notes
- Converted to repository-local guidance only.
- Kept behavior deterministic and portable across contributors.

## Provenance and license notes
- Source is public on GitHub.
- This repository stores adapted guidance, not a full upstream mirror.

