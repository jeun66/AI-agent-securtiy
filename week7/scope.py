"""Permission scopes as exact action/resource pairs for the local lab."""

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath
import re


_RESOURCE = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")


@dataclass(frozen=True, order=True, slots=True)
class Grant:
    action: str
    resource: str

    def __post_init__(self):
        if not isinstance(self.action, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", self.action):
            raise ValueError("invalid_action")
        if not isinstance(self.resource, str) or not _RESOURCE.fullmatch(self.resource):
            raise ValueError("invalid_resource")
        path = PurePosixPath(self.resource)
        if str(path) != self.resource or not path.parts or ".." in path.parts:
            raise ValueError("invalid_resource")


def encode_grants(grants: Iterable[Grant]) -> list[dict[str, str]]:
    return [{"action": grant.action, "resource": grant.resource} for grant in sorted(set(grants))]


def decode_grants(value: object) -> frozenset[Grant]:
    if not isinstance(value, list):
        raise ValueError("invalid_grants")
    grants = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"action", "resource"}:
            raise ValueError("invalid_grants")
        grant = Grant(item["action"], item["resource"])
        if grant in grants:
            raise ValueError("duplicate_grant")
        grants.add(grant)
    return frozenset(grants)
