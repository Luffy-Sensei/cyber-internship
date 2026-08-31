from __future__ import annotations

from .models import RateLimitConfig


def build_config(
    capacity: float = 3.0,
    refill_rate_per_sec: float = 0.5,
) -> RateLimitConfig:
    """Build and validate rate-limiter configuration."""

    if capacity <= 0:
        raise ValueError("Token capacity must be greater than zero.")

    if refill_rate_per_sec <= 0:
        raise ValueError("Refill rate must be greater than zero.")

    return RateLimitConfig(
        capacity=float(capacity),
        refill_rate_per_sec=float(refill_rate_per_sec),
    )
