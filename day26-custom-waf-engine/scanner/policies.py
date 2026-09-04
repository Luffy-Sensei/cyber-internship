from __future__ import annotations

from scanner.config import DEFAULT_WAF_POLICY, WAFPolicy
from scanner.models import (
    Confidence,
    Severity,
    WAFAction,
    WAFDecision,
    WAFResult,
)


class WAFPolicyEngine:
    """Convert WAF detection results into enforcement decisions."""

    _SEVERITY_RANK = {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }

    _CONFIDENCE_RANK = {
        Confidence.LOW: 1,
        Confidence.MEDIUM: 2,
        Confidence.HIGH: 3,
    }

    def __init__(
        self,
        policy: WAFPolicy = DEFAULT_WAF_POLICY,
    ) -> None:
        self.policy = policy

    def decide(self, result: WAFResult) -> WAFDecision:
        if not isinstance(result, WAFResult):
            raise TypeError("result must be a WAFResult")

        eligible_detections = tuple(
            detection
            for detection in result.detections
            if self._meets_confidence_threshold(
                detection.confidence
            )
        )

        action = self._select_action(eligible_detections)

        return WAFDecision(
            request_id=result.request_id,
            action=action,
            detections=eligible_detections,
        )

    def _select_action(self, detections) -> WAFAction:
        if not detections:
            return self.policy.default_action

        highest_severity = max(
            detections,
            key=lambda detection: self._SEVERITY_RANK[
                detection.severity
            ],
        ).severity

        if self._severity_meets_threshold(
            highest_severity,
            self.policy.block_severity,
        ):
            return WAFAction.BLOCK

        if self._severity_meets_threshold(
            highest_severity,
            self.policy.monitor_severity,
        ):
            return WAFAction.MONITOR

        return self.policy.default_action

    def _meets_confidence_threshold(
        self,
        confidence: Confidence,
    ) -> bool:
        return (
            self._CONFIDENCE_RANK[confidence]
            >= self._CONFIDENCE_RANK[
                self.policy.minimum_confidence
            ]
        )

    def _severity_meets_threshold(
        self,
        severity: Severity,
        threshold: Severity,
    ) -> bool:
        return (
            self._SEVERITY_RANK[severity]
            >= self._SEVERITY_RANK[threshold]
        )
