from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuditConfig:
    postgres_port: int = 5432
    fail_on_severity: str = "HIGH"
    redact_secrets: bool = True

    def __post_init__(self) -> None:
        if not 1 <= self.postgres_port <= 65535:
            raise ValueError("postgres_port must be between 1 and 65535")

        allowed = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

        if self.fail_on_severity not in allowed:
            raise ValueError(
                "fail_on_severity must be one of "
                + ", ".join(sorted(allowed))
            )

    @property
    def effective_postgres_port(self) -> int:
        return self.postgres_port
