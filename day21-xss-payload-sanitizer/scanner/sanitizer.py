from __future__ import annotations

import html
import re

from .models import SanitizationResult
from .rules import XSS_RULES


PROHIBITED_TOKEN = "[PROHIBITED_TOKEN]"


def detect_tokens(raw_payload: str) -> list[str]:
    """Return IDs of XSS-related rules matched by the raw input."""

    detected: list[str] = []

    for rule in XSS_RULES:
        if re.search(rule.pattern, raw_payload):
            detected.append(rule.rule_id)

    return detected


def sanitize_user_input(raw_payload: str) -> SanitizationResult:
    """
    Detect suspicious XSS constructs and produce an HTML-safe result.

    The function records the encoded representation of the original
    input separately from the final sanitized representation.

    HTML encoding is the primary defensive transformation.
    Rule-based token neutralization is supplemental and is not a
    replacement for context-specific output encoding.
    """

    if not isinstance(raw_payload, str):
        raise TypeError("Payload must be a string.")

    detected_tokens = detect_tokens(raw_payload)

    # Preserve the baseline HTML-encoded representation.
    encoded = html.escape(raw_payload, quote=True)

    # Work from the original payload so the detection regexes still
    # operate on the structural syntax they were designed to recognize.
    neutralized = raw_payload

    for rule in XSS_RULES:
        if rule.rule_id not in detected_tokens:
            continue

        neutralized = re.sub(
            rule.pattern,
            _replacement_token(rule.rule_id),
            neutralized,
        )

    # Encode the final neutralized representation for safe HTML output.
    sanitized = html.escape(neutralized, quote=True)

    return SanitizationResult(
        raw_input=raw_payload,
        encoded_output=encoded,
        sanitized_output=sanitized,
        detected_tokens=detected_tokens,
        neutralized=sanitized != raw_payload,
    )


def _replacement_token(rule_id: str) -> str:
    """Return a stable neutral marker for a detected rule."""

    return f"{PROHIBITED_TOKEN}:{rule_id}"