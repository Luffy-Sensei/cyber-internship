import pytest

from scanner.models import RateLimitConfig
from scanner.policies import (
    BURST_POLICY,
    DEFAULT_POLICY,
    STRICT_POLICY,
    get_policy,
)


def test_default_policy_exists():
    assert DEFAULT_POLICY.name == "default"
    assert DEFAULT_POLICY.config.capacity == 3.0
    assert DEFAULT_POLICY.config.refill_rate_per_sec == 0.5


def test_strict_policy_is_more_restrictive():
    assert STRICT_POLICY.config.capacity < DEFAULT_POLICY.config.capacity
    assert (
        STRICT_POLICY.config.refill_rate_per_sec
        < DEFAULT_POLICY.config.refill_rate_per_sec
    )


def test_burst_policy_allows_larger_bursts():
    assert BURST_POLICY.config.capacity > DEFAULT_POLICY.config.capacity


def test_get_policy_by_name():
    assert get_policy("default") is DEFAULT_POLICY
    assert get_policy("STRICT") is STRICT_POLICY
    assert get_policy("burst") is BURST_POLICY


def test_unknown_policy_is_rejected():
    with pytest.raises(ValueError):
        get_policy("does-not-exist")


def test_empty_policy_name_is_rejected():
    with pytest.raises(ValueError):
        get_policy("")


def test_policy_contains_valid_configuration():
    for policy in (
        DEFAULT_POLICY,
        STRICT_POLICY,
        BURST_POLICY,
    ):
        assert isinstance(policy.config, RateLimitConfig)
        assert policy.config.capacity > 0
        assert policy.config.refill_rate_per_sec > 0
