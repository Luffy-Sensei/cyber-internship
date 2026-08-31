import pytest

from scanner.config import build_config


def test_default_config():
    config = build_config()

    assert config.capacity == 3.0
    assert config.refill_rate_per_sec == 0.5


def test_custom_config():
    config = build_config(
        capacity=10,
        refill_rate_per_sec=2,
    )

    assert config.capacity == 10.0
    assert config.refill_rate_per_sec == 2.0


def test_zero_capacity_is_rejected():
    with pytest.raises(ValueError):
        build_config(capacity=0)


def test_negative_capacity_is_rejected():
    with pytest.raises(ValueError):
        build_config(capacity=-1)


def test_zero_refill_rate_is_rejected():
    with pytest.raises(ValueError):
        build_config(refill_rate_per_sec=0)


def test_negative_refill_rate_is_rejected():
    with pytest.raises(ValueError):
        build_config(refill_rate_per_sec=-1)
