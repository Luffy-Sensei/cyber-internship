from scanner.auditor import CredentialAuditor
from scanner.models import AuditTarget, CredentialRecord, Severity


def test_default_postgres_credential_generates_critical_finding():
    auditor = CredentialAuditor()
    target = AuditTarget("127.0.0.1")

    result = auditor.audit(
        target,
        [CredentialRecord("postgres", "postgres")],
    )

    assert result.status == "FINDINGS"
    assert result.passed is False
    assert result.credentials_evaluated == 1
    assert result.finding_count == 1

    finding = result.findings[0]

    assert finding.category == "DEFAULT_ADMIN_CREDENTIAL"
    assert finding.severity is Severity.CRITICAL
    assert finding.redacted_secret == "pos***"


def test_safe_application_credential_passes():
    auditor = CredentialAuditor()
    target = AuditTarget("127.0.0.1")

    result = auditor.audit(
        target,
        [CredentialRecord("app_user", "strong-random-secret")],
    )

    assert result.status == "PASS"
    assert result.passed is True
    assert result.credentials_evaluated == 1
    assert result.finding_count == 0


def test_multiple_credentials_are_evaluated():
    auditor = CredentialAuditor()
    target = AuditTarget("127.0.0.1")

    credentials = [
        CredentialRecord("postgres", "postgres"),
        CredentialRecord("app_user", "strong-random-secret"),
        CredentialRecord("admin", "admin"),
    ]

    result = auditor.audit(target, credentials)

    assert result.credentials_evaluated == 3
    assert result.finding_count == 2


def test_blank_secret_generates_critical_finding():
    auditor = CredentialAuditor()
    target = AuditTarget("127.0.0.1")

    result = auditor.audit(
        target,
        [CredentialRecord("app_user", "")],
    )

    assert result.finding_count == 1
    assert result.findings[0].category == "BLANK_CREDENTIAL"
    assert result.findings[0].severity is Severity.CRITICAL
    assert result.findings[0].redacted_secret == "<BLANK>"


def test_empty_credential_collection_passes():
    auditor = CredentialAuditor()
    target = AuditTarget("127.0.0.1")

    result = auditor.audit(target, [])

    assert result.credentials_evaluated == 0
    assert result.finding_count == 0
    assert result.passed is True
    assert result.status == "PASS"
