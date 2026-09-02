from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PipelineConfig:
    """Operational configuration for the threat-intelligence pipeline."""

    block_threshold: int = 90
    monitor_threshold: int = 70
    policy_name: str = "default-threat-block-policy"
    default_source: str = "mock-threat-feed"
    dry_run: bool = True

    def __post_init__(self) -> None:
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

        if not self.policy_name.strip():
            raise ValueError("policy_name must not be empty")

        if not self.default_source.strip():
            raise ValueError("default_source must not be empty")


def get_default_config() -> PipelineConfig:
    """Return the default safe pipeline configuration."""

    return PipelineConfig()
