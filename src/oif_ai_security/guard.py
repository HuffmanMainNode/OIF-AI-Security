"""Deny-by-default tool authorization and prompt-injection signal scanning."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

INJECTION_RULES = {
    "override_instructions": re.compile(r"\b(ignore|disregard|override)\b.{0,60}\b(instructions|rules|system prompt)\b", re.I),
    "secret_exfiltration": re.compile(r"\b(reveal|print|send|exfiltrate)\b.{0,50}\b(secret|credential|api key|password)\b", re.I),
    "role_impersonation": re.compile(r"\b(system message|developer message|new system prompt)\b", re.I),
}


def scan_untrusted_text(text: str) -> list[str]:
    """Return heuristic rule IDs. No match does not mean text is safe."""
    return [rule_id for rule_id, pattern in INJECTION_RULES.items() if pattern.search(text)]


def authorize_tool(request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    tool_name = request.get("tool")
    if not isinstance(tool_name, str) or not tool_name:
        return {"allowed": False, "reason": "missing tool name"}
    tools = policy.get("tools", {})
    if tool_name not in tools:
        return {"allowed": False, "reason": "tool is not explicitly allowlisted"}
    required = set(tools[tool_name].get("required_permissions", []))
    granted = set(policy.get("granted_permissions", []))
    missing = sorted(required - granted)
    if missing:
        return {"allowed": False, "reason": "missing required permissions", "missing_permissions": missing}
    return {"allowed": True, "reason": "allowlisted and required permissions present"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate an example AI tool policy.")
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    data = json.loads(args.input.read_text(encoding="utf-8"))
    print(json.dumps(authorize_tool(data["request"], data["policy"]), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
