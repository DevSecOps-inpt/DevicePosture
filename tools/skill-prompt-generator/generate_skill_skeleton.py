#!/usr/bin/env python3
"""Generate a repo-local SKILL.md skeleton."""

from pathlib import Path
import argparse
import re


TEMPLATE = """---
name: {name}
description: {description}
---

## Purpose
- TODO

## When to Use
- TODO

## When Not to Use
- TODO

## Required Inputs
- TODO

## Step-by-Step Workflow
1. TODO

## Expected Outputs
- TODO

## Failure and Edge-Case Handling
- TODO
"""


def slugify(value: str) -> str:
    text = value.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return text or "new-skill"


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a local skill skeleton.")
    parser.add_argument("name", help="Skill name")
    parser.add_argument("description", help="Skill one-line description")
    parser.add_argument(
        "--root",
        default=".agents/skills",
        help="Skills root directory (default: .agents/skills)",
    )
    args = parser.parse_args()

    slug = slugify(args.name)
    target_dir = Path(args.root) / slug
    target_file = target_dir / "SKILL.md"
    target_dir.mkdir(parents=True, exist_ok=True)

    if target_file.exists():
        raise SystemExit(f"Refusing to overwrite existing file: {target_file}")

    target_file.write_text(
        TEMPLATE.format(name=slug, description=args.description.strip()),
        encoding="utf-8",
    )
    print(target_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

