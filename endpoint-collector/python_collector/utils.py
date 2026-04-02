import json
import subprocess
from typing import Any


def ensure_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def run_powershell_json(script: str, timeout: int = 20) -> Any:
    command = ["powershell", "-NoProfile", "-Command", script]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )
    stdout = result.stdout.strip()
    if not stdout:
        return None
    return json.loads(stdout)
