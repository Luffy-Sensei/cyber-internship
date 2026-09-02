from __future__ import annotations

from dataclasses import dataclass

from .config import PipelineConfig
from .models import FirewallAction, FirewallDecision, ThreatIndicator


@dataclass(frozen=True)
class ThreatPolicy:
    """Evaluate threat indicators against configured risk thresholds."""

    name: str
    block_threshold: int
    monitor_threshold: int

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("policy name must not be empty")

        if not 0 <= self.block_threshold <= 100:
            raise ValueError(
                "block_threshold must be between 0 and 100"
            )

        if not 0 <= self.monitor_threshold <= 100:
            raise ValueError(
                "monitor_threshold must be between 0 and 100"
            )

        if self.monitor_threshold > self.block_threshold:
            raise ValueError(
                "monitor_threshold must not exceed block_threshold"
            )

    def evaluate(
        self,
        indicator: ThreatIndicator,
    ) -> FirewallDecision:
        """Evaluate an indicator and produce a policy decision."""

        if indicator.risk_score >= self.block_threshold:
            return FirewallDecision(
                ip=indicator.ip,
                indicator=indicator.indicator,
                action=FirewallAction.BLOCK,
                reason=(
                    "Risk score meets or exceeds the configured "
                    "blocking threshold."
                ),
                risk_score=indicator.risk_score,
                policy=self.name,
            )

        if indicator.risk_score >= self.monitor_threshold:
            return FirewallDecision(
                ip=indicator.ip,
                indicator=indicator.indicator,
                action=FirewallAction.MONITOR,
                reason=(
                    "Risk score meets or exceeds the monitoring "
                    "threshold but remains below the blocking threshold."
                ),
                risk_score=indicator.risk_score,
                policy=self.name,
            )

        return FirewallDecision(
            ip=indicator.ip,
            indicator=indicator.indicator,
            action=FirewallAction.IGNORE,
            reason=(
                "Risk score is below the configured monitoring "
                "threshold."
            ),
            risk_score=indicator.risk_score,
            policy=self.name,
        )


def get_default_policy(
    config: PipelineConfig | None = None,
) -> ThreatPolicy:
    """Build a threat policy from pipeline configuration."""

    active_config = config or PipelineConfig()

    return ThreatPolicy(
        name=active_config.policy_name,
        block_threshold=active_config.block_threshold,
        monitor_threshold=active_config.monitor_threshold,
    )
