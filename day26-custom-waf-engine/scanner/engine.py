from __future__ import annotations

from scanner.models import (
    HTTPRequest,
    WAFResult,
)
from scanner.rules import WAFRuleEngine


class WAFDetectionEngine:
    """Orchestrate normalization and rule-based request inspection."""

    def __init__(self, rule_engine: WAFRuleEngine) -> None:
        self.rule_engine = rule_engine

    def inspect(self, request: HTTPRequest) -> WAFResult:
        if not isinstance(request, HTTPRequest):
            raise TypeError("request must be an HTTPRequest")

        detections = self.rule_engine.inspect(request)

        return WAFResult(
            request_id=request.request_id,
            detections=detections,
        )
