from __future__ import annotations

from dataclasses import dataclass

from scanner.models import (
    Confidence,
    RuleCategory,
    Severity,
    WAFAction,
    WAFRule,
)


@dataclass(frozen=True)
class WAFPolicy:
    block_severity: Severity = Severity.HIGH
    monitor_severity: Severity = Severity.MEDIUM
    default_action: WAFAction = WAFAction.ALLOW
    minimum_confidence: Confidence = Confidence.MEDIUM
    inspect_query: bool = True
    inspect_headers: bool = True
    inspect_body: bool = True
    inspect_path: bool = True

    def __post_init__(self) -> None:
        if self.block_severity is Severity.LOW:
            raise ValueError(
                "block_severity must not be LOW"
            )

        if self.monitor_severity is Severity.HIGH:
            raise ValueError(
                "monitor_severity must be below HIGH"
            )


DEFAULT_WAF_POLICY = WAFPolicy()


DEFAULT_WAF_RULES: tuple[WAFRule, ...] = (
    WAFRule(
        rule_id="SQLI-001",
        category=RuleCategory.SQLI,
        pattern=r"(?i)union\s+select",
        severity=Severity.HIGH,
        description="Detects a UNION SELECT SQL injection indicator.",
    ),
    WAFRule(
        rule_id="XSS-001",
        category=RuleCategory.XSS,
        pattern=r"(?i)<\s*script\b",
        severity=Severity.HIGH,
        description="Detects a script-tag XSS indicator.",
    ),
    WAFRule(
        rule_id="TRAVERSAL-001",
        category=RuleCategory.PATH_TRAVERSAL,
        pattern=r"(?i)(?:\.\./|\.\.\\)",
        severity=Severity.HIGH,
        description="Detects a directory traversal indicator.",
    ),
)
