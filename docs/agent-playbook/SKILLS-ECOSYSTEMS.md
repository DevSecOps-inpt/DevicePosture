# Skills Ecosystems Guidance

## Local-first default
- Prefer local skills under `.agents/skills/` by default.
- Treat local skills as the authoritative operational layer for this repository.

## External ecosystems policy
- External skills are reference sources, not runtime dependencies.
- Distill useful guidance into local durable assets before operational use.
- Do not rely on hidden global state (for example `~/.agents`, `~/.codex`) for normal execution.

## Adoption workflow
1. Consult upstream source minimally.
2. Extract only necessary guidance.
3. Adapt to local constraints and repo conventions.
4. Record provenance under `.agents/skills/_meta/`.
5. Verify local artifacts exist and can be used offline.

## Revisit policy
- Revisit upstream sources only when explicitly requested.
- During ordinary execution, use local assets and playbooks only.

