from __future__ import annotations

from dataclasses import dataclass

from .models import SanitizationResult
from .rules import XSS_RULES


@dataclass(frozen=True)
class IntelligenceResult:
    """Contextual security assessment of a sanitized payload."""

    xss_model: str
    context: str
    severity: str
    confidence: str
    detected_tokens: list[str]
    rationale: str


_SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def analyze_payload(
    result: SanitizationResult,
    *,
    context: str = "UNKNOWN",
    xss_model: str = "UNKNOWN",
) -> IntelligenceResult:
    """
    Produce contextual intelligence from a sanitizer result.

    XSS model classification is only asserted when supplied by an
    external execution/context layer. A payload alone cannot prove
    Stored, Reflected, or DOM-based XSS.
    """

    if not isinstance(result, SanitizationResult):
        raise TypeError("result must be a SanitizationResult.")

    normalized_context = context.upper()
    normalized_model = xss_model.upper()

    valid_contexts = {
        "HTML",
        "ATTRIBUTE",
        "JAVASCRIPT",
        "URL",
        "DOM",
        "UNKNOWN",
    }

    valid_models = {
        "STORED",
        "REFLECTED",
        "DOM_BASED",
        "UNKNOWN",
    }

    if normalized_context not in valid_contexts:
        raise ValueError(f"Unsupported context: {context}")

    if normalized_model not in valid_models:
        raise ValueError(f"Unsupported XSS model: {xss_model}")

    severity = _highest_rule_severity(result.detected_tokens)

    if not result.detected_tokens:
        severity = "LOW"

    confidence = _calculate_confidence(
        result=result,
        context=normalized_context,
        xss_model=normalized_model,
    )

    rationale = _build_rationale(
        result=result,
        context=normalized_context,
        xss_model=normalized_model,
        severity=severity,
    )

    return IntelligenceResult(
        xss_model=normalized_model,
        context=normalized_context,
        severity=severity,
        confidence=confidence,
        detected_tokens=list(result.detected_tokens),
        rationale=rationale,
    )


def _highest_rule_severity(detected_tokens: list[str]) -> str:
    """Return the highest severity represented by detected rules."""

    severities: list[str] = []

    for rule in XSS_RULES:
        if rule.rule_id in detected_tokens:
            severities.append(rule.severity)

    if not severities:
        return "LOW"

    return max(
        severities,
        key=lambda severity: _SEVERITY_ORDER.get(severity, 0),
    )


def _calculate_confidence(
    *,
    result: SanitizationResult,
    context: str,
    xss_model: str,
) -> str:
    """Calculate confidence without overstating payload-only evidence."""

    if not result.detected_tokens:
        return "HIGH"

    if context != "UNKNOWN" and xss_model != "UNKNOWN":
        return "HIGH"

    if context != "UNKNOWN" or xss_model != "UNKNOWN":
        return "MEDIUM"

    return "MEDIUM"


def _build_rationale(
    *,
    result: SanitizationResult,
    context: str,
    xss_model: str,
    severity: str,
) -> str:
    """Create a concise explanation for the assessment."""

    if not result.detected_tokens:
        return "No configured XSS indicators were detected."

    tokens = ", ".join(result.detected_tokens)

    if xss_model == "UNKNOWN":
        model_note = (
            "Payload evidence alone cannot establish whether the "
            "issue is Stored, Reflected, or DOM-based XSS."
        )
    else:
        model_note = f"Context supplied for assessment: {xss_model} XSS."

    return (
        f"Detected tokens: {tokens}. "
        f"Highest rule severity: {severity}. "
        f"Output context: {context}. "
        f"{model_note}"
    )
