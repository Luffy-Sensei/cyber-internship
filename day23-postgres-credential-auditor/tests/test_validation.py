from pathlib import Path

from scanner.auditor import CredentialAuditor
from scanner.models import AuditTarget, CredentialRecord
from scanner.validation import load_fixtures


FIXTURE = Path("input/credential-fixtures.json")


def test_fixture_loader():
    target, credentials = load_fixtures(FIXTURE)

    assert target == AuditTarget("127.0.0.1", 5432, "postgresql")
    assert len(credentials) == 5


def test_fixture_validation_detects_expected_findings():
    target, credentials = load_fixtures(FIXTURE)

    result = CredentialAuditor().audit(target, credentials)

    assert result.credentials_evaluated == 5
    assert result.finding_count == 3
    assert result.passed is False


def test_fixture_contains_safe_application_credential():
    target, credentials = load_fixtures(FIXTURE)

    safe = [
        item
        for item in credentials
        if item.username == "app_user"
    ]

    result = CredentialAuditor().audit(target, safe)

    assert result.passed is True
    assert result.finding_count == 0
