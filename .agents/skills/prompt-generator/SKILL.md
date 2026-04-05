---
name: prompt-generator
description: Use to generate new repo-local skill skeletons and prompt drafts from a consistent template.
---

## Purpose
Create consistent local skill scaffolds and prompt drafts for repeatable agent behavior.

## When to Use
- Creating a new skill under `.agents/skills/`.
- Standardizing prompt structure for future reuse.
- Converting ad-hoc instructions into durable assets.

## When Not to Use
- Editing product code that does not require new prompt/skill assets.
- One-off chat-only instructions.

## Required Inputs
- Skill name.
- One-line skill description.
- Intended audience and workflow steps.

## Step-by-Step Workflow
1. Use `tools/skill-prompt-generator/generate_skill_skeleton.py` to create initial scaffold.
2. Fill required sections with repository-specific guidance.
3. Validate front matter keys are exactly `name` and `description`.
4. Add provenance note if content was adapted from an upstream source.
5. Verify created file path and readability.

## Expected Outputs
- A valid `SKILL.md` with required sections.
- Prompt scaffolds that can be reused in `.codex/prompts/`.

## Failure and Edge-Case Handling
- If script execution fails, create the file manually using the same template.
- If skill name conflicts with existing folder, update in place instead of duplicating.
- If required inputs are missing, generate placeholders and flag them clearly.

