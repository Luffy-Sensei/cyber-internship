from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SanitizationResult:
    """Result produced by the XSS payload sanitizer."""

    raw_input: str
    encoded_output: str
    sanitized_output: str
    detected_tokens: list[str] = field(default_factory=list)
    neutralized: bool = False
