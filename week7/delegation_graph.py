"""Build a Mermaid diagram from a verified audit event's delegation path."""

from week7.identity import resolve_did_key
from week7.scope import decode_grants


def delegation_markdown(event: dict) -> str:
    delegation = event.get("delegation")
    if not isinstance(delegation, dict):
        raise ValueError("audit_delegation_missing")
    path, edges = delegation.get("path"), delegation.get("grants")
    if not isinstance(path, list) or not isinstance(edges, list) or not edges or len(path) != len(edges) + 1:
        raise ValueError("invalid_audit_delegation")
    for did in path:
        resolve_did_key(did)

    labels = ["사용자", "상위 에이전트", "하위 에이전트"] if len(path) == 3 else [
        "사용자", *(f"에이전트 {number}" for number in range(1, len(path))),
    ]
    diagram = ["# 검증된 위임 경로", "", "```mermaid", "flowchart LR"]
    for index, label in enumerate(labels):
        diagram.append(f'    n{index}["{label}"]')
    for index, raw_grants in enumerate(edges):
        grants = sorted(decode_grants(raw_grants))
        scope = ", ".join(f"{grant.action} {grant.resource}" for grant in grants)
        diagram.append(f'    n{index} -->|"{scope or "권한 없음"}"| n{index + 1}')
    diagram.extend(["```", "", "| 역할 | DID |", "| --- | --- |"])
    diagram.extend(f"| {label} | `{did}` |" for label, did in zip(labels, path))
    return "\n".join(diagram) + "\n"
