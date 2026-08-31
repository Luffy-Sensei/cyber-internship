from scanner.models import RateLimitConfig, RateLimitDecision


def test_rate_limit_config_stores_values():
    config = RateLimitConfig(
        capacity=3,
        refill_rate_per_sec=0.5,
    )

    assert config.capacity == 3
    assert config.refill_rate_per_sec == 0.5


def test_rate_limit_decision_defaults():
    decision = RateLimitDecision(
        client_id="127.0.0.1",
        allowed=True,
        remaining_tokens=2.0,
    )

    assert decision.allowed is True
    assert decision.remaining_tokens == 2.0
    assert decision.retry_after_seconds == 0.0
