from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class XSSRule:
    """Definition of a suspicious XSS-related token or construct."""

    rule_id: str
    pattern: str
    description: str
    severity: str


XSS_RULES: tuple[XSSRule, ...] = (
    XSSRule(
        rule_id="SCRIPT_TAG",
        pattern=r"(?i)<\s*/?\s*script\b",
        description="HTML script element detected.",
        severity="CRITICAL",
    ),
    XSSRule(
        rule_id="EVENT_HANDLER",
        pattern=r"(?i)\bon(?:error|load|click|mouseover|focus|submit)\s*=",
        description="Inline browser event handler detected.",
        severity="HIGH",
    ),
    XSSRule(
        rule_id="JAVASCRIPT_SCHEME",
        pattern=r"(?i)\bjavascript\s*:",
        description="JavaScript URI scheme detected.",
        severity="CRITICAL",
    ),
    XSSRule(
        rule_id="IFRAME_TAG",
        pattern=r"(?i)<\s*/?\s*iframe\b",
        description="Iframe element detected.",
        severity="HIGH",
    ),
    XSSRule(
        rule_id="SVG_TAG",
        pattern=r"(?i)<\s*/?\s*svg\b",
        description="SVG element detected.",
        severity="MEDIUM",
    ),
    XSSRule(
        rule_id="OBJECT_TAG",
        pattern=r"(?i)<\s*/?\s*object\b",
        description="Object element detected.",
        severity="HIGH",
    ),
)
