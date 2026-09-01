from scanner.models import CredentialRecord, Severity
from scanner.policies import CredentialPolicy, get_default_policy


def test_default_postgres_credential_is_critical():
    policy = get_default_policy()

    findings = policy.evaluate(
        CredentialRecord("postgres", "postgres")
    )

    assert len(findings) == 1
    assert findings[0][0] == "DEFAULT_ADMIN_CREDENTIAL"
    assert findings[0][1] is Severity.CRITICAL


def test_blank_secret_is_critical():
    policy = CredentialPolicy()

    findings = policy.evaluate(
        CredentialRecord("app_user", "")
    )

    assert len(findings) == 1
    assert findings[0][0] == "BLANK_CREDENTIAL"
    assert findings[0][1] is Severity.CRITICAL


def test_admin_admin_is_high():
    policy = CredentialPolicy()

    findings = policy.evaluate(
        CredentialRecord("admin", "admin")
    )

    assert len(findings) == 1
    assert findings[0][0] == "ADMIN_DEFAULT_CREDENTIAL"
    assert findings[0][1] is Severity.HIGH


def test_safe_credential_has_no_findings():
    policy = CredentialPolicy()

    findings = policy.evaluate(
        CredentialRecord("app_user", "strong-random-secret")
    )

    assert findings == []
