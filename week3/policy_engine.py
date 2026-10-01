from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import yaml

WEEK3_DIR = Path(__file__).resolve().parent
POLICY_PATH = WEEK3_DIR / "policy.yaml"
SANDBOX_DIR = (Path(__file__).resolve().parents[1] / "week2" / "sandbox").resolve()


def load_policy(path: str | Path = POLICY_PATH) -> dict:
    with Path(path).open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data


def _relative_read_target(path_value: str) -> Path:
    return (SANDBOX_DIR / path_value).resolve()


def check_policy(name: str, args: dict) -> str:
    decision, _reason = evaluate_policy(name, args)
    return decision


def evaluate_policy(name: str, args: dict) -> tuple[str, str]:
    policy = load_policy(POLICY_PATH)
    tool_rules = policy.get("tools", {}).get(name, {})
    default = policy.get("default", "deny")

    if name == "read_file":
        path_value = args.get("path")
        if not isinstance(path_value, str):
            return "deny", "missing_path"
        try:
            target = _relative_read_target(path_value)
        except Exception:
            return "deny", "invalid_path"
        if not target.is_relative_to(SANDBOX_DIR):
            return "deny", "path_outside_sandbox"
        return "allow", "path_allowlisted"

    if name == "http_get":
        url_value = args.get("url")
        if not isinstance(url_value, str):
            return "deny", "missing_url"
        try:
            hostname = urlsplit(url_value).hostname
        except ValueError:
            return "deny", "invalid_url"
        if hostname is None:
            return "deny", "missing_hostname"
        if hostname in tool_rules.get("deny_hosts", []):
            return "deny", "host_denied"
        if hostname in tool_rules.get("allow_hosts", []):
            return "allow", "host_allowlisted"
        if policy.get("approval", {}).get("enabled"):
            return "approval", "host_requires_manual_review"
        return "deny", "host_not_allowlisted"

    if not tool_rules and default == "deny":
        return "deny", "tool_not_allowlisted"

    return default, "default_policy"
