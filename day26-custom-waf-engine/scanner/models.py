from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class WAFAction(str, Enum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    BLOCK = "BLOCK"


class RuleCategory(str, Enum):
    SQLI = "SQLI"
    XSS = "XSS"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class HTTPRequest:
    request_id: str
    method: str
    path: str
    query: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    def __post_init__(self) -> None:
        if not self.request_id.strip():
            raise ValueError("request_id must not be empty")

        if not self.method.strip():
            raise ValueError("method must not be empty")

        if not self.path.strip():
            raise ValueError("path must not be empty")

        if not isinstance(self.headers, dict):
            raise TypeError("headers must be a dictionary")


@dataclass(frozen=True)
class WAFRule:
    rule_id: str
    category: RuleCategory
    pattern: str
    severity: Severity
    description: str
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise ValueError("rule_id must not be empty")

        if not self.pattern.strip():
            raise ValueError("pattern must not be empty")

        if not self.description.strip():
            raise ValueError("description must not be empty")


@dataclass(frozen=True)
class WAFDetection:
    rule_id: str
    category: RuleCategory
    severity: Severity
    matched_field: str
    evidence: str
    confidence: Confidence

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise ValueError("rule_id must not be empty")

        if not self.matched_field.strip():
            raise ValueError("matched_field must not be empty")

        if not self.evidence.strip():
            raise ValueError("evidence must not be empty")

@dataclass(frozen=True)
class WAFResult:
    request_id: str
    detections: tuple[WAFDetection, ...]

    @property
    def detected(self) -> bool:
        return bool(self.detections)

    @property
    def detection_count(self) -> int:
        return len(self.detections)

@dataclass(frozen=True)
class WAFDecision:
    request_id: str
    action: WAFAction
    detections: tuple[WAFDetection, ...] = ()

    def __post_init__(self) -> None:
        if not self.request_id.strip():
            raise ValueError("request_id must not be empty")

        if not isinstance(self.detections, tuple):
            raise TypeError("detections must be a tuple")
