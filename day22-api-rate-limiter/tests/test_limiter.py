from scanner.config import build_config
from scanner.limiter import TokenBucketRateLimiter


class FakeClock:
    """Deterministic clock for rate-limiter tests."""

    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def build_limiter(clock):
    config = build_config(
        capacity=3,
        refill_rate_per_sec=0.5,
    )

    return TokenBucketRateLimiter(
        config=config,
        clock=clock,
    )


def test_client_can_consume_initial_capacity():
    clock = FakeClock()
    limiter = build_limiter(clock)

    results = [
        limiter.allow_request("client-A")
        for _ in range(3)
    ]

    assert all(result.allowed for result in results)
    assert results[-1].remaining_tokens == 0.0


def test_request_is_denied_when_bucket_is_empty():
    clock = FakeClock()
    limiter = build_limiter(clock)

    for _ in range(3):
        limiter.allow_request("client-A")

    result = limiter.allow_request("client-A")

    assert result.allowed is False
    assert result.remaining_tokens == 0.0
    assert result.retry_after_seconds == 2.0


def test_tokens_refill_over_time():
    clock = FakeClock()
    limiter = build_limiter(clock)

    for _ in range(3):
        limiter.allow_request("client-A")

    clock.advance(2.0)

    result = limiter.allow_request("client-A")

    assert result.allowed is True
    assert result.remaining_tokens == 0.0


def test_bucket_never_exceeds_capacity():
    clock = FakeClock()
    limiter = build_limiter(clock)

    first = limiter.get_client_state("client-A")

    assert first.remaining_tokens == 3.0

    clock.advance(100.0)

    state = limiter.get_client_state("client-A")

    assert state.remaining_tokens == 3.0


def test_clients_have_independent_buckets():
    clock = FakeClock()
    limiter = build_limiter(clock)

    for _ in range(3):
        limiter.allow_request("client-A")

    denied = limiter.allow_request("client-A")
    allowed = limiter.allow_request("client-B")

    assert denied.allowed is False
    assert allowed.allowed is True


def test_fractional_refill_is_supported():
    clock = FakeClock()
    limiter = build_limiter(clock)

    for _ in range(3):
        limiter.allow_request("client-A")

    clock.advance(1.0)

    state = limiter.get_client_state("client-A")

    assert state.remaining_tokens == 0.5


def test_empty_client_id_is_rejected():
    clock = FakeClock()
    limiter = build_limiter(clock)

    try:
        limiter.allow_request("")
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError")
