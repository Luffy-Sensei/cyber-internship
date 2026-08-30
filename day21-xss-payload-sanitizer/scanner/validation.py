from __future__ import annotations

from dataclasses import dataclass

from .models import SanitizationResult
from .sanitizer import PROHIBITED_TOKEN, sanitize_user_input


@dataclass(frozen=True)
class ValidationResult:
    """Result of adversarial sanitizer validation."""

    payload: str
    passed: bool
    detected_tokens: list[str]
    neutralized: bool
    sanitized_output: str
    reason: str


def validate_payload(payload: str) -> ValidationResult:
    """
    Validate one payload against the configured sanitizer.

    A payload passes when:
      - it is safely transformed when active XSS constructs are found;
      - prohibited structural constructs are not preserved; or
      - ordinary input remains unchanged.
    """

    result = sanitize_user_input(payload)

    if not isinstance(result, SanitizationResult):
        raise TypeError("Sanitizer returned an invalid result.")

    if result.detected_tokens:
        token_markers = [
            f"{PROHIBITED_TOKEN}:{token}"
            for token in result.detected_tokens
        ]

        marker_present = any(
            marker in result.sanitized_output
            for marker in token_markers
        )

        passed = result.neutralized and marker_present

        if passed:
            reason = "Detected XSS constructs were neutralized and encoded."
        else:
            reason = (
                "XSS constructs were detected but the expected "
                "neutralization marker was not preserved."
            )

    else:
        passed = result.sanitized_output == result.encoded_output
        reason = (
            "No configured XSS tokens detected; output remains "
            "HTML-encoded according to the sanitizer policy."
        )

    return ValidationResult(
        payload=payload,
        passed=passed,
        detected_tokens=list(result.detected_tokens),
        neutralized=result.neutralized,
        sanitized_output=result.sanitized_output,
        reason=reason,
    )


def validate_payloads(payloads: list[str]) -> list[ValidationResult]:
    """Validate a collection of payloads."""

    return [validate_payload(payload) for payload in payloads]
