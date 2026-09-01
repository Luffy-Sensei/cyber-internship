from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .models import AuditFinding, AuditTarget, CredentialRecord
from .policies import CredentialPolicy, get_default_policy


@dataclass(frozen=True)
class AuditResult:
    target: AuditTarget
    credentials_evaluated: int
    findings: tuple[AuditFinding, ...]

    @property
    def passed(self) -> bool:
        return len(self.findings) == 0

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def status(self) -> str:
        return "PASS" if self.passed else "FINDINGS"


class CredentialAuditor:
    """Evaluate supplied PostgreSQL credential records against security policy.

    This component performs policy analysis only. It does not attempt
    authentication against a remote PostgreSQL service.
    """

    def __init__(
        self,
        policy: CredentialPolicy | None = None,
    ) -> None:
        self.policy = policy or get_default_policy()

    def audit(
        self,
        target: AuditTarget,
        credentials: Iterable[CredentialRecord],
    ) -> AuditResult:
        findings: list[AuditFinding] = []
        evaluated = 0

        for credential in credentials:
            evaluated += 1

            policy_findings = self.policy.evaluate(credential)

            for category, severity, message in policy_findings:
                findings.append(
                    AuditFinding(
                        category=category,
                        severity=severity,
                        username=credential.username,
                        message=message,
                        redacted_secret=credential.redacted_secret,
                    )
                )

        return AuditResult(
            target=target,
            credentials_evaluated=evaluated,
            findings=tuple(findings),
        )
