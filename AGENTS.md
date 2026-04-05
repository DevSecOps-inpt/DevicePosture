# Repository Agent Guidance

## Scope and durability
- Bootstrap and setup tasks must keep durable agent assets inside this repository.
- Prefer repo-local skills in `.agents/skills/` over repeated prompt prose.
- Prefer repo-local Codex config in `.codex/config.toml`.

## Task tracking policy
- Do not use flat markdown trackers for granular execution (for example: `TODO.md`, `PLAN.md`, `STATUS.md`, `TASKS.md`).
- Use Beads for granular execution tracking.

## Beads workflow
1. `bd ready --json`
2. `bd update <id> --claim`
3. `bd create "Task Name" --deps discovered-from:<parent_id>`
4. `bd close <id> --reason "Completed"`

## Beads safety rules
- Detect existing `.beads` state before making Beads changes.
- Prefer standalone/default Beads first unless the repository is already server-backed or clearly needs multi-writer access.
- Never run `bd init --force` automatically.
- Never delete `.beads/dolt`, run blind repair, or reinitialize as a default recovery step.
- `bd --version` is not sufficient proof; verify with a real Beads command.

## Host-boundary rule
- If a Beads or Dolt step fails because sandbox cannot reach localhost or a host-only daemon, do not treat it as a repository failure.
- Record the exact blocked command and exact error.
- Request rerun through:
  - `./tools/host/beads-host ...`

## Verification rule
- Verify created files and directories after creation.
- Use the repository's obvious verification command if one exists.
- If verification is undefined, state that explicitly.

## Safe editing rule
- Do not overwrite unrelated user-authored files.
- During bootstrap, do not modify product runtime behavior, pipeline behavior, CI/CD behavior, deployment behavior, or production configuration.

