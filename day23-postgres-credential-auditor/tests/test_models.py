import pytest

from scanner.models import AuditFinding, AuditTarget, CredentialRecord, Severity


def test_audit_target_defaults():
    target = AuditTarget("127.0.0.1")

    assert target.host == "127.0.0.1"
    assert target.port == 5432
    assert target.service == "postgresql"


def test_invalid_target_port():
    with pytest.raises(ValueError):
        AuditTarget("127.0.0.1", 70000)


def test_credential_redaction():
    credential = CredentialRecord("postgres", "postgres")

    assert credential.redacted_secret == "pos***"
    assert "postgres" not in repr(credential)


def test_blank_secret_redaction():
    credential = CredentialRecord("postgres", "")

    assert credential.redacted_secret == "<BLANK>"


def test_finding_model():
    finding = AuditFinding(
        category="DEFAULT_ADMIN_CREDENTIAL",
        severity=Severity.CRITICAL,
        username="postgres",
        message="Default credential detected.",
        redacted_secret="pos***",
    )

    assert finding.severity is Severity.CRITICAL
