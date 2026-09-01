import pytest

from scanner.config import AuditConfig


def test_default_config():
    config = AuditConfig()

    assert config.postgres_port == 5432
    assert config.fail_on_severity == "HIGH"
    assert config.redact_secrets is True


def test_invalid_port():
    with pytest.raises(ValueError):
        AuditConfig(postgres_port=0)


def test_invalid_severity():
    with pytest.raises(ValueError):
        AuditConfig(fail_on_severity="INVALID")
