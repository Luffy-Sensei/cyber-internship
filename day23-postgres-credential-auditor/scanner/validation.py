from __future__ import annotations

import argparse
import json
from pathlib import Path

from .auditor import CredentialAuditor
from .models import AuditTarget, CredentialRecord
from .reporting import ReportWriter


DEFAULT_FIXTURE = Path("input/credential-fixtures.json")


def load_fixtures(
    path: Path,
) -> tuple[AuditTarget, list[CredentialRecord]]:
    data = json.loads(path.read_text(encoding="utf-8"))

    target_data = data["target"]

    target = AuditTarget(
        host=target_data["host"],
        port=target_data["port"],
        service=target_data.get("service", "postgresql"),
    )

    credentials = [
        CredentialRecord(
            username=item["username"],
            secret=item["secret"],
        )
        for item in data["credentials"]
    ]

    return target, credentials


def run_validation(path: Path) -> int:
    target, credentials = load_fixtures(path)

    auditor = CredentialAuditor()
    result = auditor.audit(target, credentials)

    safe_credentials = [
        credential
        for credential in credentials
        if credential.username == "app_user"
    ]

    safe_result = auditor.audit(
        target,
        safe_credentials,
    )

    validation_status = (
        "VALIDATED"
        if result.finding_count == 3 and safe_result.passed
        else "VALIDATION_FAILED"
    )

    report_writer = ReportWriter(
        policy=auditor.policy,
    )

    json_path, txt_path = report_writer.write_reports(
        result,
        validation_status=validation_status,
    )

    print("=" * 60)
    print("DAY 23 - POSTGRES CREDENTIAL AUDIT VALIDATION")
    print("=" * 60)
    print()
    print(f"Target       : {target.host}:{target.port}")
    print(f"Credentials  : {result.credentials_evaluated}")
    print(f"Findings     : {result.finding_count}")
    print(f"Status       : {result.status}")
    print()

    print("FINDINGS")
    print("-" * 60)

    for finding in result.findings:
        print(
            f"{finding.severity.value:<8} "
            f"{finding.category:<30} "
            f"user={finding.username:<15} "
            f"secret={finding.redacted_secret}"
        )

    print()
    print("SAFE CREDENTIAL CHECK")
    print("-" * 60)

    print(
        f"app_user -> "
        f"{'PASS' if safe_result.passed else 'FINDING'}"
    )

    print()
    print("EVIDENCE")
    print("-" * 60)
    print(f"JSON       : {json_path}")
    print(f"TXT        : {txt_path}")
    print(
        "LOG        : "
        "output/logs/day23_credential_audit.log"
    )
    print()
    print(f"Validation : {validation_status}")

    return 0 if validation_status == "VALIDATED" else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the controlled Day 23 "
            "credential audit validation."
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_FIXTURE,
        help="Path to the controlled JSON fixture.",
    )

    args = parser.parse_args()

    return run_validation(args.input)


if __name__ == "__main__":
    raise SystemExit(main())