import pytest

from scanner.config import PipelineConfig, get_default_config


def test_default_config():
    config = get_default_config()

    assert config.block_threshold == 90
    assert config.monitor_threshold == 70
    assert config.dry_run is True
    assert config.policy_name == "default-threat-block-policy"


def test_config_rejects_invalid_block_threshold():
    with pytest.raises(ValueError):
        PipelineConfig(block_threshold=101)


def test_config_rejects_invalid_monitor_threshold():
    with pytest.raises(ValueError):
        PipelineConfig(monitor_threshold=101)


def test_config_rejects_reversed_thresholds():
    with pytest.raises(ValueError):
        PipelineConfig(
            block_threshold=50,
            monitor_threshold=60,
        )


def test_config_accepts_equal_thresholds():
    config = PipelineConfig(
        block_threshold=80,
        monitor_threshold=80,
    )

    assert config.block_threshold == 80
    assert config.monitor_threshold == 80


def test_config_rejects_empty_policy_name():
    with pytest.raises(ValueError):
        PipelineConfig(policy_name="   ")


def test_config_rejects_empty_source():
    with pytest.raises(ValueError):
        PipelineConfig(default_source="   ")
