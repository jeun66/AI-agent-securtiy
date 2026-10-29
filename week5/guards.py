"""Backend-neutral MCP-Guard hooks. This module never downloads a model."""
from dataclasses import dataclass
import math
import re
from typing import Optional, Protocol, Tuple


@dataclass(frozen=True)
class GuardRequest:
    direction: str
    text: str
    context: str = ""
    tool_name: str = ""
    sources: Tuple[str, ...] = ()

    def __post_init__(self):
        if self.direction not in ("input", "output"):
            raise ValueError("direction must be input or output")
        if not isinstance(self.text, str) or not isinstance(self.context, str):
            raise TypeError("guard text and context must be strings")


@dataclass(frozen=True)
class Finding:
    label: str
    score: Optional[float] = None
    start: Optional[int] = None
    end: Optional[int] = None

    def __post_init__(self):
        if not isinstance(self.label, str) or not self.label:
            raise ValueError("finding requires a label")
        if self.score is not None and (
            isinstance(self.score, bool) or not math.isfinite(self.score)
            or not 0 <= self.score <= 1
        ):
            raise ValueError("score must be finite and in [0, 1]")
        if (self.start is None) != (self.end is None):
            raise ValueError("span requires both offsets")
        if self.start is not None and not (0 <= self.start < self.end):
            raise ValueError("invalid span")

    def to_log(self):
        return {"label": self.label, "score": self.score,
                "start": self.start, "end": self.end}


@dataclass(frozen=True)
class GuardResult:
    decision: str
    backend: str
    kind: str
    findings: Tuple[Finding, ...] = ()
    reason: str = "checked"

    def __post_init__(self):
        if self.decision not in ("allow", "block"):
            raise ValueError("guard decision must be allow or block")
        if self.kind not in ("rule", "mock", "model") or not self.backend:
            raise ValueError("guard must identify its backend and execution kind")
        if not isinstance(self.findings, tuple) or not all(isinstance(f, Finding) for f in self.findings):
            raise TypeError("findings must be a tuple of Finding objects")

    def to_log(self):
        # Deliberately omit original text, matched PII, credentials and prompts.
        return {"decision": self.decision, "backend": self.backend,
                "kind": self.kind, "reason": self.reason,
                "findings": [f.to_log() for f in self.findings]}


class Guard(Protocol):
    name: str
    kind: str

    def check(self, request: GuardRequest) -> GuardResult:
        ...


class RuleGuard:
    """Real local regex checks; a smoke baseline, not a trained classifier."""
    name = "local-rules-v1"
    kind = "rule"
    input_rules = (
        ("prompt_injection", r"ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|이전\s*(?:지시|명령).{0,16}무시"),
        ("jailbreak", r"\bjailbreak\b|\bDAN\s+mode\b|안전\s*(?:규칙|제한).{0,16}(?:해제|우회)"),
        ("system_prompt_extraction", r"(?:reveal|print|show).{0,30}system\s+prompt|시스템\s*프롬프트.{0,20}(?:출력|보여|공개)"),
    )
    output_rules = (
        ("resident_id", r"\b\d{6}-[1-8]\d{6}\b"),
        ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        ("secret", r"\bR3_CANARY_SECRET=[A-Za-z0-9_-]+|\bsk-[A-Za-z0-9_-]{20,}"),
    )

    def check(self, request):
        text = request.text + ("\n" + request.context if request.direction == "input" else "")
        rules = self.input_rules if request.direction == "input" else self.output_rules
        hits = tuple(Finding(label, start=m.start(), end=m.end())
                     for label, pattern in rules
                     for m in re.finditer(pattern, text, re.IGNORECASE))
        if request.direction == "output":
            from week5.prompts import HARDENED_SYSTEM_PROMPT
            pos = request.text.find(HARDENED_SYSTEM_PROMPT)
            if pos >= 0:
                hits += (Finding("system_prompt", start=pos, end=pos + len(HARDENED_SYSTEM_PROMPT)),)
        return GuardResult("block" if hits else "allow", self.name, self.kind, hits)


class MockGuard:
    """Explicit fixed-response test double. It performs no text detection."""
    name = "mock-fixed"
    kind = "mock"

    def __init__(self, decision="allow"):
        # Validate immediately, so a mock cannot silently accept malformed config.
        GuardResult(decision, self.name, self.kind)
        self.decision = decision

    def check(self, request):
        return GuardResult(self.decision, self.name, self.kind, reason="fixed_test_response")
