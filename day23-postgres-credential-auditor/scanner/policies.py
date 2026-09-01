from __future__ import annotations

from dataclasses import dataclass

from .models import CredentialRecord, Severity


@dataclass(frozen=True)
class CredentialPolicy:
    name: str = "postgres-default-credential-policy"

    default_admin_username: str = "postgres"
    default_admin_secret: str = "postgres"

    blank_secret_severity: Severity = Severity.CRITICAL
    default_admin_severity: Severity = Severity.CRITICAL
    admin_like_default_severity: Severity = Severity.HIGH

    admin_like_pairs: tuple[tuple[str, str], ...] = (
        ("admin", "admin"),
    )

    def evaluate(self, credential: CredentialRecord) -> list[tuple[str, Severity, str]]:
        findings: list[tuple[str, Severity, str]] = []

        if not credential.secret:
            findings.append(
                (
                    "BLANK_CREDENTIAL",
                    self.blank_secret_severity,
                    "Database credential uses a blank secret.",
                )
            )

        if (
            credential.username == self.default_admin_username
            and credential.secret == self.default_admin_secret
        ):
            findings.append(
                (
                    "DEFAULT_ADMIN_CREDENTIAL",
                    self.default_admin_severity,
                    "Known default PostgreSQL administrative credential pattern detected.",
                )
            )

        if (credential.username, credential.secret) in self.admin_like_pairs:
            findings.append(
                (
                    "ADMIN_DEFAULT_CREDENTIAL",
                    self.admin_like_default_severity,
                    "Predictable administrative credential pattern detected.",
                )
            )

        return findings


def get_default_policy() -> CredentialPolicy:
    return CredentialPolicy()
