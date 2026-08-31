from __future__ import annotations

from dataclasses import dataclass, field

from .limiter import TokenBucketRateLimiter
from .models import RateLimitDecision
from .policies import RateLimitPolicy


@dataclass
class EngineStatistics:
    """Aggregate request statistics."""

    total_requests: int = 0
    allowed_requests: int = 0
    denied_requests: int = 0
    clients_seen: set[str] = field(default_factory=set)


class RateLimitEngine:
    """Operational layer around a token-bucket rate limiter."""

    def __init__(
        self,
        policy: RateLimitPolicy,
        clock=None,
    ) -> None:
        self.policy = policy

        if clock is None:
            self.limiter = TokenBucketRateLimiter(
                config=policy.config,
            )
        else:
            self.limiter = TokenBucketRateLimiter(
                config=policy.config,
                clock=clock,
            )

        self.statistics = EngineStatistics()

    def process_request(
        self,
        client_id: str,
    ) -> RateLimitDecision:
        """Process one request and update execution statistics."""

        decision = self.limiter.allow_request(client_id)

        self.statistics.total_requests += 1
        self.statistics.clients_seen.add(client_id)

        if decision.allowed:
            self.statistics.allowed_requests += 1
        else:
            self.statistics.denied_requests += 1

        return decision

    def process_requests(
        self,
        client_id: str,
        request_count: int,
    ) -> list[RateLimitDecision]:
        """Process multiple requests for one client."""

        if request_count < 0:
            raise ValueError("request_count cannot be negative.")

        return [
            self.process_request(client_id)
            for _ in range(request_count)
        ]

    def summary(self) -> dict[str, object]:
        """Return aggregate execution statistics."""

        return {
            "policy": self.policy.name,
            "total_requests": self.statistics.total_requests,
            "allowed_requests": self.statistics.allowed_requests,
            "denied_requests": self.statistics.denied_requests,
            "clients_seen": len(self.statistics.clients_seen),
        }
