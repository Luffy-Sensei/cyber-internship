import json
from pathlib import Path

from scanner.auditor import CredentialAuditor
from scanner.models import AuditTarget, CredentialRecord
from scanner.policies import get_default_policy
from scanner.reporting import ReportWriter


def build_result():
    target = AuditTarget(
        host="127.0.0.1",
        port=5432,
    )

    credentials = [
        CredentialRecord("postgres", "postgres"),
        CredentialRecord("postgres", ""),
        CredentialRecord("admin", "admin"),
        CredentialRecord("app_user", "SecureP@ss2026!"),
        CredentialRecord("readonly", "safe-secret"),
    ]

    auditor = CredentialAuditor(get_default_policy())

    return auditor.audit(target, credentials)


def test_json_report_is_created(tmp_path: Path):
    result = build_result()

    writer = ReportWriter(
        get_default_policy(),
        report_dir=tmp_path / "reports",
        log_dir=tmp_path / "logs",
    )

    json_path, _ = writer.write_reports(result)

    assert json_path.exists()

    data = json.loads(json_path.read_text(encoding="utf-8"))

    assert data["finding_count"] == 3
    assert data["accounts_evaluated"] == 5


def test_txt_report_is_created(tmp_path: Path):
    result = build_result()

    writer = ReportWriter(
        get_default_policy(),
        report_dir=tmp_path / "reports",
        log_dir=tmp_path / "logs",
    )

    _, txt_path = writer.write_reports(result)

    assert txt_path.exists()

    content = txt_path.read_text(encoding="utf-8")

    assert "DAY 23 - POSTGRES CREDENTIAL AUDIT REPORT" in content
    assert "DEFAULT_ADMIN_CREDENTIAL" in content
    assert "BLANK_CREDENTIAL" in content
    assert "ADMIN_DEFAULT_CREDENTIAL" in content


def test_audit_id_and_timestamp_are_present(tmp_path: Path):
    result = build_result()

    writer = ReportWriter(
        get_default_policy(),
        report_dir=tmp_path / "reports",
        log_dir=tmp_path / "logs",
    )

    json_path, _ = writer.write_reports(result)

    data = json.loads(json_path.read_text(encoding="utf-8"))

    assert data["audit_id"]
    assert len(data["audit_id"]) == 36
    assert data["timestamp"].endswith("+00:00")


def test_target_is_serialized(tmp_path: Path):
    result = build_result()

    writer = ReportWriter(
        get_default_policy(),
        report_dir=tmp_path / "reports",
        log_dir=tmp_path / "logs",
    )

    json_path, _ = writer.write_reports(result)

    data = json.loads(json_path.read_text(encoding="utf-8"))

    assert data["target"] == {
        "host": "127.0.0.1",
        "port": 5432,
        "service": "postgresql",
    }


def test_severity_summary_is_correct(tmp_path: Path):
    result = build_result()

    writer = ReportWriter(
        get_default_policy(),
        report_dir=tmp_path / "reports",
        log_dir=tmp_path / "logs",
    )

    json_path, _ = writer.write_reports(result)

    data = json.loads(json_path.read_text(encoding="utf-8"))

    assert data["severity_summary"]["CRITICAL"] == 2
    assert data["severity_summary"]["HIGH"] == 1
    assert data["severity_summary"]["MEDIUM"] == 0
    assert data["severity_summary"]["LOW"] == 0
    assert data["severity_summary"]["INFO"] == 0


def test_policy_is_serialized_without_raw_secret(tmp_path: Path):
    result = build_result()

    writer = ReportWriter(
        get_default_policy(),
        report_dir=tmp_path / "reports",
        log_dir=tmp_path / "logs",
    )

    json_path, _ = writer.write_reports(result)

    data = json.loads(json_path.read_text(encoding="utf-8"))

    assert data["policy"]["name"] == (
        "postgres-default-credential-policy"
    )

    assert "default_admin_secret" not in data["policy"]


def test_raw_secrets_never_appear_in_json_or_txt(tmp_path: Path):
    result = build_result()

    writer = ReportWriter(
        get_default_policy(),
        report_dir=tmp_path / "reports",
        log_dir=tmp_path / "logs",
    )

    json_path, txt_path = writer.write_reports(result)

    json_content = json_path.read_text(encoding="utf-8")
    txt_content = txt_path.read_text(encoding="utf-8")

    raw_secrets = [
        "postgres",
        "admin",
        "SecureP@ss2026!",
        "safe-secret",
    ]

    # Usernames are intentionally present as finding metadata.
    # Therefore check the actual secret values specifically.
    assert "SecureP@ss2026!" not in json_content
    assert "SecureP@ss2026!" not in txt_content
    assert "safe-secret" not in json_content
    assert "safe-secret" not in txt_content

    # The default password must not be serialized as policy configuration.
    assert '"default_admin_secret"' not in json_content


def test_redacted_secrets_are_present(tmp_path: Path):
    result = build_result()

    writer = ReportWriter(
        get_default_policy(),
        report_dir=tmp_path / "reports",
        log_dir=tmp_path / "logs",
    )

    json_path, txt_path = writer.write_reports(result)

    json_content = json_path.read_text(encoding="utf-8")
    txt_content = txt_path.read_text(encoding="utf-8")

    assert "pos***" in json_content
    assert "pos***" in txt_content
    assert "<BLANK>" in json_content
    assert "<BLANK>" in txt_content
    assert "adm***" in json_content
    assert "adm***" in txt_content


def test_validation_status_can_be_overridden(tmp_path: Path):
    result = build_result()

    writer = ReportWriter(
        get_default_policy(),
        report_dir=tmp_path / "reports",
        log_dir=tmp_path / "logs",
    )

    json_path, _ = writer.write_reports(
        result,
        validation_status="VALIDATED",
    )

    data = json.loads(json_path.read_text(encoding="utf-8"))

    assert data["validation_status"] == "VALIDATED"


def test_output_directories_are_created(tmp_path: Path):
    result = build_result()

    report_dir = tmp_path / "nested" / "reports"
    log_dir = tmp_path / "nested" / "logs"

    writer = ReportWriter(
        get_default_policy(),
        report_dir=report_dir,
        log_dir=log_dir,
    )

    writer.write_reports(result)

    assert report_dir.is_dir()
    assert log_dir.is_dir()


def test_report_generation_is_logged(tmp_path: Path):
    result = build_result()

    log_dir = tmp_path / "logs"

    writer = ReportWriter(
        get_default_policy(),
        report_dir=tmp_path / "reports",
        log_dir=log_dir,
    )

    writer.write_reports(result)

    log_path = log_dir / "day23_credential_audit.log"

    assert log_path.exists()

    content = log_path.read_text(encoding="utf-8")

    assert "Credential audit reports generated" in content
    assert "Report log stored at" in content
