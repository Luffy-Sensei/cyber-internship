from __future__ import annotations

import time
from dataclasses import dataclass

from .models import RateLimitConfig, RateLimitDecision


@dataclass
class _BucketState:
    """Internal state for one client bucket."""

    tokens: float
    last_updated: float


class TokenBucketRateLimiter:
    """Per-client token bucket rate limiter."""

    def __init__(
        self,
        config: RateLimitConfig,
        clock=time.monotonic,
    ) -> None:
        self.config = config
        self.clock = clock
        self._ledger: dict[str, _BucketState] = {}

    def allow_request(self, client_id: str) -> RateLimitDecision:
        """Evaluate whether a request from client_id should be allowed."""

        if not isinstance(client_id, str) or not client_id.strip():
            raise ValueError("client_id must be a non-empty string.")

        now = self.clock()

        state = self._ledger.get(client_id)

        if state is None:
            state = _BucketState(
                tokens=self.config.capacity,
                last_updated=now,
            )
            self._ledger[client_id] = state

        self._refill(state, now)

        if state.tokens >= 1.0:
            state.tokens -= 1.0

            return RateLimitDecision(
                client_id=client_id,
                allowed=True,
                remaining_tokens=state.tokens,
            )

        retry_after = (
            1.0 - state.tokens
        ) / self.config.refill_rate_per_sec

        return RateLimitDecision(
            client_id=client_id,
            allowed=False,
            remaining_tokens=state.tokens,
            retry_after_seconds=retry_after,
        )

    def _refill(
        self,
        state: _BucketState,
        now: float,
    ) -> None:
        """Refill a bucket according to elapsed time."""

        elapsed = max(0.0, now - state.last_updated)

        state.tokens = min(
            self.config.capacity,
            state.tokens + (
                elapsed * self.config.refill_rate_per_sec
            ),
        )

        state.last_updated = now

    def get_client_state(
        self,
        client_id: str,
    ) -> RateLimitDecision:
        """Return the current state without consuming a token."""

        state = self._ledger.get(client_id)

        if state is None:
            return RateLimitDecision(
                client_id=client_id,
                allowed=True,
                remaining_tokens=self.config.capacity,
            )

        now = self.clock()
        self._refill(state, now)

        return RateLimitDecision(
            client_id=client_id,
            allowed=True,
            remaining_tokens=state.tokens,
        )
