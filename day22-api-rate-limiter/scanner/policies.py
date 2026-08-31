from __future__ import annotations

from dataclasses import dataclass

from .models import RateLimitConfig


@dataclass(frozen=True)
class RateLimitPolicy:
    """Named rate-limiting policy."""

    name: str
    config: RateLimitConfig
    description: str


DEFAULT_POLICY = RateLimitPolicy(
    name="default",
    config=RateLimitConfig(
        capacity=3.0,
        refill_rate_per_sec=0.5,
    ),
    description="Balanced policy for general API traffic.",
)


STRICT_POLICY = RateLimitPolicy(
    name="strict",
    config=RateLimitConfig(
        capacity=2.0,
        refill_rate_per_sec=0.25,
    ),
    description="Restrictive policy for sensitive endpoints.",
)


BURST_POLICY = RateLimitPolicy(
    name="burst",
    config=RateLimitConfig(
        capacity=10.0,
        refill_rate_per_sec=2.0,
    ),
    description="Higher burst allowance for trusted workloads.",
)


POLICIES: dict[str, RateLimitPolicy] = {
    DEFAULT_POLICY.name: DEFAULT_POLICY,
    STRICT_POLICY.name: STRICT_POLICY,
    BURST_POLICY.name: BURST_POLICY,
}


def get_policy(name: str) -> RateLimitPolicy:
    """Return a configured policy by name."""

    if not isinstance(name, str) or not name.strip():
        raise ValueError("Policy name must be a non-empty string.")

    try:
        return POLICIES[name.lower()]
    except KeyError as exc:
        available = ", ".join(sorted(POLICIES))
        raise ValueError(
            f"Unknown policy '{name}'. Available policies: {available}."
        ) from exc
