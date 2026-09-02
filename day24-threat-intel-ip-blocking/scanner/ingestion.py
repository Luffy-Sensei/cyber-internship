from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

from .models import ThreatFeed, ThreatIndicator


class FeedIngestionError(ValueError):
    """Raised when a threat-intelligence feed fails validation."""


class ThreatFeedIngestor:
    """Load and validate a controlled threat-intelligence feed.

    The ingestor converts untrusted JSON data into strongly typed
    ThreatFeed and ThreatIndicator objects.

    No firewall actions are performed by this component.
    """

    def load_file(self, path: str | Path) -> ThreatFeed:
        """Load a JSON threat feed from disk."""

        feed_path = Path(path)

        if not feed_path.is_file():
            raise FeedIngestionError(
                f"threat feed does not exist: {feed_path}"
            )

        try:
            with feed_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except json.JSONDecodeError as exc:
            raise FeedIngestionError(
                f"invalid JSON feed: {feed_path}"
            ) from exc

        return self.parse(payload)

    def parse(self, payload: Any) -> ThreatFeed:
        """Validate and convert a decoded feed payload."""

        if not isinstance(payload, dict):
            raise FeedIngestionError(
                "feed root must be a JSON object"
            )

        feed_id = payload.get("feed_id")
        source = payload.get("source")
        indicators = payload.get("indicators")

        if not isinstance(feed_id, str) or not feed_id.strip():
            raise FeedIngestionError(
                "feed_id must be a non-empty string"
            )

        if not isinstance(source, str) or not source.strip():
            raise FeedIngestionError(
                "source must be a non-empty string"
            )

        if not isinstance(indicators, list):
            raise FeedIngestionError(
                "indicators must be a JSON array"
            )

        parsed_indicators: list[ThreatIndicator] = []

        for index, entry in enumerate(indicators):
            parsed_indicators.append(
                self._parse_indicator(
                    entry,
                    source=source,
                    index=index,
                )
            )

        return ThreatFeed(
            source=source,
            indicators=tuple(parsed_indicators),
            feed_id=feed_id,
        )

    def _parse_indicator(
        self,
        entry: Any,
        *,
        source: str,
        index: int,
    ) -> ThreatIndicator:
        """Validate and convert one feed indicator."""

        if not isinstance(entry, dict):
            raise FeedIngestionError(
                f"indicator[{index}] must be a JSON object"
            )

        ip = entry.get("ip")
        indicator = entry.get("indicator")
        risk_score = entry.get("risk_score")

        if not isinstance(ip, str) or not ip.strip():
            raise FeedIngestionError(
                f"indicator[{index}].ip must be a non-empty string"
            )

        self._validate_ipv4(ip, index)

        if not isinstance(indicator, str) or not indicator.strip():
            raise FeedIngestionError(
                f"indicator[{index}].indicator must be a non-empty string"
            )

        if isinstance(risk_score, bool) or not isinstance(
            risk_score,
            int,
        ):
            raise FeedIngestionError(
                f"indicator[{index}].risk_score must be an integer"
            )

        if not 0 <= risk_score <= 100:
            raise FeedIngestionError(
                f"indicator[{index}].risk_score must be between 0 and 100"
            )

        return ThreatIndicator(
            ip=ip,
            indicator=indicator,
            risk_score=risk_score,
            source=source,
        )

    @staticmethod
    def _validate_ipv4(ip: str, index: int) -> None:
        """Reject anything that is not a valid IPv4 address."""

        try:
            address = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise FeedIngestionError(
                f"indicator[{index}].ip is not a valid IP address: {ip}"
            ) from exc

        if address.version != 4:
            raise FeedIngestionError(
                f"indicator[{index}].ip must be IPv4: {ip}"
            )
