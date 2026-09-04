from __future__ import annotations

import re
from dataclasses import dataclass

from scanner.models import (
    Confidence,
    HTTPRequest,
    WAFDetection,
    WAFRule,
)
from scanner.normalizer import NormalizedRequest, RequestNormalizer


@dataclass(frozen=True)
class CompiledWAFRule:
    rule: WAFRule
    pattern: re.Pattern[str]


class WAFRuleEngine:
    """Evaluate normalized HTTP requests against configured WAF rules."""

    INSPECTABLE_FIELDS = (
        "path",
        "query",
        "headers",
        "body",
    )

    def __init__(
        self,
        rules: tuple[WAFRule, ...],
        normalizer: RequestNormalizer | None = None,
    ) -> None:
        self.normalizer = normalizer or RequestNormalizer()
        self.rules = tuple(
            self._compile_rule(rule)
            for rule in rules
            if rule.enabled
        )

    @staticmethod
    def _compile_rule(rule: WAFRule) -> CompiledWAFRule:
        try:
            pattern = re.compile(rule.pattern)
        except re.error as exc:
            raise ValueError(
                f"Invalid regex for rule {rule.rule_id}: {exc}"
            ) from exc

        return CompiledWAFRule(
            rule=rule,
            pattern=pattern,
        )

    def inspect(
        self,
        request: HTTPRequest | NormalizedRequest,
    ) -> tuple[WAFDetection, ...]:
        if isinstance(request, HTTPRequest):
            normalized = self.normalizer.normalize(request)
        elif isinstance(request, NormalizedRequest):
            normalized = request
        else:
            raise TypeError(
                "request must be an HTTPRequest "
                "or NormalizedRequest"
            )

        detections: list[WAFDetection] = []

        for compiled_rule in self.rules:
            detections.extend(
                self._inspect_rule(
                    compiled_rule,
                    normalized,
                )
            )

        return tuple(detections)

    def _inspect_rule(
        self,
        compiled_rule: CompiledWAFRule,
        request: NormalizedRequest,
    ) -> list[WAFDetection]:
        detections: list[WAFDetection] = []

        for field_name, value in self._iter_fields(request):
            match = compiled_rule.pattern.search(value)

            if match is None:
                continue

            evidence = self._build_evidence(
                value,
                match.start(),
                match.end(),
            )

            detections.append(
                WAFDetection(
                    rule_id=compiled_rule.rule.rule_id,
                    category=compiled_rule.rule.category,
                    severity=compiled_rule.rule.severity,
                    matched_field=field_name,
                    evidence=evidence,
                    confidence=Confidence.HIGH,
                )
            )

        return detections

    def _iter_fields(
        self,
        request: NormalizedRequest,
    ):
        yield "path", request.path
        yield "query", request.query
        yield "body", request.body

        for name, value in request.headers.items():
            yield f"header:{name}", value

    @staticmethod
    def _build_evidence(
        value: str,
        start: int,
        end: int,
    ) -> str:
        matched = value[start:end]

        max_length = 120

        if len(matched) <= max_length:
            return matched

        return matched[:max_length]
