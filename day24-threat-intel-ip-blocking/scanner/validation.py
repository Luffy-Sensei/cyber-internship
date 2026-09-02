from __future__ import annotations

import ipaddress
from typing import Any

from .models import (
    RejectedIndicator,
    ThreatIndicator,
    ValidationResult,
)


class ValidationEngine:
    """Validate threat-intelligence indicators independently.

    Unlike ThreatFeedIngestor.parse(), this engine intentionally evaluates
    each indicator independently so that malformed records can be rejected
    without preventing valid intelligence from continuing through the
    policy pipeline.

    Rejected indicators never reach policy evaluation or the firewall
    adapter.
    """

    def validate(
        self,
        *,
        feed_id: str,
        source: str,
        indicators: list[Any],
    ) -> ValidationResult:
        if not feed_id.strip():
            raise ValueError("feed_id must not be empty")

        if not source.strip():
            raise ValueError("source must not be empty")

        valid: list[ThreatIndicator] = []
        rejected: list[RejectedIndicator] = []

        for index, entry in enumerate(indicators):
            try:
                valid.append(
                    self._validate_indicator(
                        entry,
                        source=source,
                        index=index,
                    )
                )
            except ValueError as exc:
                rejected.append(
                    RejectedIndicator(
                        index=index,
                        reason=str(exc),
                        raw_entry=entry,
                    )
                )

        return ValidationResult(
            feed_id=feed_id,
            source=source,
            valid_indicators=tuple(valid),
            rejected_indicators=tuple(rejected),
        )

    def _validate_indicator(
        self,
        entry: Any,
        *,
        source: str,
        index: int,
    ) -> ThreatIndicator:
        if not isinstance(entry, dict):
            raise ValueError(
                f"indicator[{index}] must be a JSON object"
            )

        ip = entry.get("ip")
        indicator = entry.get("indicator")
        risk_score = entry.get("risk_score")

        if not isinstance(ip, str) or not ip.strip():
            raise ValueError(
                f"indicator[{index}].ip must be a non-empty string"
            )

        try:
            address = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError(
                f"indicator[{index}].ip is invalid: {ip}"
            ) from exc

        if address.version != 4:
            raise ValueError(
                f"indicator[{index}].ip must be IPv4: {ip}"
            )

        if not isinstance(indicator, str) or not indicator.strip():
            raise ValueError(
                f"indicator[{index}].indicator must be a non-empty string"
            )

        if isinstance(risk_score, bool) or not isinstance(
            risk_score,
            int,
        ):
            raise ValueError(
                f"indicator[{index}].risk_score must be an integer"
            )

        if not 0 <= risk_score <= 100:
            raise ValueError(
                f"indicator[{index}].risk_score must be between 0 and 100"
            )

        return ThreatIndicator(
            ip=ip,
            indicator=indicator,
            risk_score=risk_score,
            source=source,
        )
