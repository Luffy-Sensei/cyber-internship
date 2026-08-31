from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitConfig:
    """Configuration for a token-bucket rate limiter."""

    capacity: float
    refill_rate_per_sec: float


@dataclass(frozen=True)
class RateLimitDecision:
    """Result of evaluating one request."""

    client_id: str
    allowed: bool
    remaining_tokens: float
    retry_after_seconds: float = 0.0
