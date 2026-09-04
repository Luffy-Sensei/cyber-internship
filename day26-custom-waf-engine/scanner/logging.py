from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from scanner.models import WAFDecision


class WAFAuditLogger:
    """Write structured WAF audit events as JSON Lines."""

    def __init__(self, log_path: Path) -> None:
        self.log_path = Path(log_path)

    def log_decision(
        self,
        decision: WAFDecision,
        *,
        method: str,
        path: str,
    ) -> None:
        self.log_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        event = self._build_event(
            decision,
            method=method,
            path=path,
        )

        with self.log_path.open(
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write(
                json.dumps(
                    event,
                    sort_keys=True,
                )
                + "\n"
            )

    @staticmethod
    def _build_event(
        decision: WAFDecision,
        *,
        method: str,
        path: str,
    ) -> dict[str, object]:
        detections = [
            {
                "rule_id": detection.rule_id,
                "category": detection.category.value,
                "severity": detection.severity.value,
                "matched_field": detection.matched_field,
                "evidence": detection.evidence,
                "confidence": detection.confidence.value,
            }
            for detection in decision.detections
        ]

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": decision.request_id,
            "method": method,
            "path": path,
            "detections": detections,
            "detection_count": len(detections),
            "action": decision.action.value,
            "rules_triggered": [
                detection["rule_id"]
                for detection in detections
            ],
        }
