from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FirewallAction(str, Enum):
    """Supported policy outcomes for a threat indicator."""

    BLOCK = "BLOCK"
    MONITOR = "MONITOR"
    IGNORE = "IGNORE"


class FirewallMode(str, Enum):
    """Firewall adapter execution modes."""

    DRY_RUN = "DRY-RUN"
    APPLY = "APPLY"


class RuleStatus(str, Enum):
    """Status of a proposed or processed firewall rule."""

    PROPOSED = "PROPOSED"
    SKIPPED = "SKIPPED"


@dataclass(frozen=True)
class ThreatIndicator:
    """A single threat-intelligence indicator."""

    ip: str
    indicator: str
    risk_score: int
    source: str

    def __post_init__(self) -> None:
        if not self.ip.strip():
            raise ValueError("ip must not be empty")

        if not self.indicator.strip():
            raise ValueError("indicator must not be empty")

        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")

        if not self.source.strip():
            raise ValueError("source must not be empty")


@dataclass(frozen=True)
class ThreatFeed:
    """A collection of threat indicators from one intelligence source."""

    source: str
    indicators: tuple[ThreatIndicator, ...]
    feed_id: str = "mock-threat-feed"

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError("source must not be empty")

        if not self.feed_id.strip():
            raise ValueError("feed_id must not be empty")


@dataclass(frozen=True)
class FirewallDecision:
    """Policy decision produced for a threat indicator."""

    ip: str
    indicator: str
    action: FirewallAction
    reason: str
    risk_score: int
    policy: str

    def __post_init__(self) -> None:
        if not self.ip.strip():
            raise ValueError("ip must not be empty")

        if not self.indicator.strip():
            raise ValueError("indicator must not be empty")

        if not self.reason.strip():
            raise ValueError("reason must not be empty")

        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")

        if not self.policy.strip():
            raise ValueError("policy must not be empty")


@dataclass(frozen=True)
class BlockRule:
    """Normalized firewall rule representation.

    This object describes a rule but does not apply it to a real firewall.
    """

    ip: str
    indicator: str
    reason: str
    source: str
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.ip.strip():
            raise ValueError("ip must not be empty")
        if not self.indicator.strip():
            raise ValueError("indicator must not be empty")
        if not self.reason.strip():
            raise ValueError("reason must not be empty")
        if not self.source.strip():
            raise ValueError("source must not be empty")


@dataclass(frozen=True)
class FirewallExecution:
    """Audit record for firewall adapter processing.

    This is an execution record, not evidence that a host firewall
    was actually modified.
    """

    ip: str
    indicator: str
    action: FirewallAction
    mode: FirewallMode
    status: RuleStatus
    reason: str
    risk_score: int
    policy: str
    rule: BlockRule | None = None

    def __post_init__(self) -> None:
        if not self.ip.strip():
            raise ValueError("ip must not be empty")

        if not self.reason.strip():
            raise ValueError("reason must not be empty")

        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")

        if not self.policy.strip():
            raise ValueError("policy must not be empty")
@dataclass(frozen=True)
class RejectedIndicator:
    """Record describing a threat indicator rejected during validation."""

    index: int
    reason: str
    raw_entry: object

    def __post_init__(self) -> None:
        if self.index < 0:
            raise ValueError("index must not be negative")

        if not self.reason.strip():
            raise ValueError("reason must not be empty")


@dataclass(frozen=True)
class ValidationResult:
    """Result of record-level threat-intelligence validation."""

    feed_id: str
    source: str
    valid_indicators: tuple[ThreatIndicator, ...]
    rejected_indicators: tuple[RejectedIndicator, ...]

    @property
    def indicators_received(self) -> int:
        return (
            len(self.valid_indicators)
            + len(self.rejected_indicators)
        )

    @property
    def indicators_valid(self) -> int:
        return len(self.valid_indicators)

    @property
    def indicators_rejected(self) -> int:
        return len(self.rejected_indicators)

    @property
    def passed(self) -> bool:
        return self.indicators_rejected == 0

    @property
    def status(self) -> str:
        return "VALIDATED" if self.passed else "VALIDATED_WITH_REJECTIONS"