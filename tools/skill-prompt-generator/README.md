# Local Skill Prompt Generator

This local helper generates a new `SKILL.md` skeleton that matches repository rules.

Usage:

```bash
python tools/skill-prompt-generator/generate_skill_skeleton.py "Skill Name" "One-line description"
```

Behavior:
- Creates a folder under `.agents/skills/<slug>/`.
- Creates `SKILL.md` with required front matter and required sections.
- Refuses to overwrite existing files.

