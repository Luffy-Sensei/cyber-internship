from __future__ import annotations

from dataclasses import dataclass

from .models import SanitizationResult
from .rules import XSS_RULES


@dataclass(frozen=True)
class SecurityFinding:
    """Security interpretation of a sanitized payload."""

    rule_id: str
    severity: str
    classification: str
    message: str
    recommendation: str


class XSSAnalyzer:
    """Convert sanitizer results into actionable security findings."""

    def __init__(self) -> None:
        self._rules = {
            rule.rule_id: rule
            for rule in XSS_RULES
        }

    def analyze(
        self,
        result: SanitizationResult,
    ) -> list[SecurityFinding]:
        """Return findings associated with detected XSS constructs."""

        findings: list[SecurityFinding] = []

        for rule_id in result.detected_tokens:
            rule = self._rules[rule_id]

            findings.append(
                SecurityFinding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    classification=self._classification(rule.rule_id),
                    message=rule.description,
                    recommendation=self._recommendation(rule.rule_id),
                )
            )

        return findings

    @staticmethod
    def _classification(rule_id: str) -> str:
        classifications = {
            "SCRIPT_TAG": "SCRIPT_INJECTION",
            "EVENT_HANDLER": "EVENT_HANDLER_INJECTION",
            "JAVASCRIPT_SCHEME": "JAVASCRIPT_URI_INJECTION",
            "IFRAME_TAG": "ACTIVE_CONTENT_INJECTION",
            "SVG_TAG": "ACTIVE_MARKUP_INJECTION",
            "OBJECT_TAG": "ACTIVE_CONTENT_INJECTION",
        }

        return classifications.get(
            rule_id,
            "XSS_SUSPICIOUS_INPUT",
        )

    @staticmethod
    def _recommendation(rule_id: str) -> str:
        recommendations = {
            "SCRIPT_TAG": (
                "Apply context-appropriate output encoding and "
                "avoid inserting untrusted input into executable "
                "script contexts."
            ),
            "EVENT_HANDLER": (
                "Avoid inline event handlers and use safe event "
                "binding mechanisms with trusted data."
            ),
            "JAVASCRIPT_SCHEME": (
                "Reject unsafe URI schemes and allowlist expected "
                "protocols such as HTTPS where appropriate."
            ),
            "IFRAME_TAG": (
                "Do not permit untrusted iframe markup; apply "
                "contextual output encoding and an appropriate CSP."
            ),
            "SVG_TAG": (
                "Treat untrusted SVG markup as active content and "
                "sanitize or encode it according to its output context."
            ),
            "OBJECT_TAG": (
                "Do not allow untrusted object/embed markup and "
                "restrict active content through output controls."
            ),
        }

        return recommendations.get(
            rule_id,
            "Apply contextual output encoding and validate untrusted input.",
        )
