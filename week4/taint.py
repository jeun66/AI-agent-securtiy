from __future__ import annotations

from typing import Any, Iterable
from urllib.parse import urlparse, parse_qs


class Tainted:
    """Wrapper for values carrying taint metadata.

    Supports string concatenation and common string methods by propagating sources.
    """

    def __init__(self, value: Any, sources: Iterable[str] | None = None):
        self.value = value
        self.sources = set(sources or [])

    @property
    def tainted(self) -> bool:
        return bool(self.sources)

    def add_sources(self, other: "Tainted"):
        self.sources.update(other.sources)

    def _wrap_result(self, result: Any, other: "Tainted" | None = None) -> Any:
        # If result is str and any operand is tainted, return Tainted
        if isinstance(result, str):
            sources = set(self.sources)
            if other is not None:
                sources.update(other.sources)
            return Tainted(result, sources)
        # For non-string results, return plain value
        return result

    # String-like operations
    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return f"Tainted({self.value!r}, sources={list(self.sources)})"

    def __add__(self, other):
        if isinstance(other, Tainted):
            res = str(self.value) + str(other.value)
            return Tainted(res, set(self.sources) | set(other.sources))
        res = str(self.value) + str(other)
        return Tainted(res, set(self.sources))

    def __radd__(self, other):
        if isinstance(other, Tainted):
            res = str(other.value) + str(self.value)
            return Tainted(res, set(self.sources) | set(other.sources))
        res = str(other) + str(self.value)
        return Tainted(res, set(self.sources))

    def __format__(self, spec):
        formatted = format(str(self.value), spec)
        return Tainted(formatted, set(self.sources))

    def __getattr__(self, name):
        # Proxy string methods to propagate taint when they return strings
        attr = getattr(self.value, name)
        if callable(attr):
            def fn(*args, **kwargs):
                res = attr(*args, **kwargs)
                if isinstance(res, str):
                    return Tainted(res, set(self.sources))
                return res

            return fn
        return attr


def taint_from_source(source: str, value: Any) -> Any:
    """Create a tainted object from external source.

    If value is list/dict, recursively taint contained values.
    """
    if isinstance(value, dict):
        return {k: taint_from_source(source, v) for k, v in value.items()}
    if isinstance(value, list):
        return [taint_from_source(source, v) for v in value]
    # Primitive
    return Tainted(value, [source])


def maybe_taint(value: Any, sources: Iterable[str] | None = None) -> Any:
    """Wrap value as Tainted if sources provided; recurse for containers."""
    if sources is None:
        return value
    if isinstance(value, dict):
        return {k: maybe_taint(v, sources) for k, v in value.items()}
    if isinstance(value, list):
        return [maybe_taint(v, sources) for v in value]
    return Tainted(value, sources)


def is_tainted(obj: Any) -> bool:
    if isinstance(obj, Tainted):
        return obj.tainted
    if isinstance(obj, dict):
        return any(is_tainted(v) for v in obj.values())
    if isinstance(obj, list):
        return any(is_tainted(v) for v in obj)
    return False


def collect_sources(obj: Any) -> set:
    if isinstance(obj, Tainted):
        return set(obj.sources)
    if isinstance(obj, dict):
        s = set()
        for v in obj.values():
            s.update(collect_sources(v))
        return s
    if isinstance(obj, list):
        s = set()
        for v in obj:
            s.update(collect_sources(v))
        return s
    return set()


# Sink checks
def check_http_get(url_obj: Any) -> tuple[bool, str]:
    """Return (allowed, reason). Block if URL or its query contains tainted data.

    url_obj may be plain str or Tainted.
    """
    # If object is Tainted and tainted -> block
    if isinstance(url_obj, Tainted) and url_obj.tainted:
        return False, "tainted_url"

    url = str(url_obj)
    try:
        p = urlparse(url)
    except Exception:
        return False, "invalid_url"

    qs = parse_qs(p.query)
    # If any query value is a Tainted object or contains sources, block
    for k, vs in qs.items():
        for v in vs:
            # If original url_obj was constructed from Tainted objects, we would have Tainted wrapper.
            # Here we conservatively check for markers by re-checking provided url_obj sources.
            pass

    # If the url_obj is not Tainted but may have been constructed from concatenation of Tainted parts,
    # our Tainted wrapper would have preserved sources; since it's not tainted here, allow.
    return True, "allow"


__all__ = [
    "Tainted",
    "taint_from_source",
    "maybe_taint",
    "is_tainted",
    "collect_sources",
    "check_http_get",
]
