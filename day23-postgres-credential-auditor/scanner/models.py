from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class AuditTarget:
    host: str
    port: int = 5432
    service: str = "postgresql"

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise ValueError("host must not be empty")

        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")


@dataclass(frozen=True, repr=False)
class CredentialRecord:
    username: str
    secret: str

    def __post_init__(self) -> None:
        if not self.username.strip():
            raise ValueError("username must not be empty")

    @property
    def redacted_secret(self) -> str:
        if not self.secret:
            return "<BLANK>"

        if len(self.secret) <= 3:
            return "***"

        return f"{self.secret[:3]}***"

    def __repr__(self) -> str:
        return "CredentialRecord(<REDACTED>)"


@dataclass(frozen=True)
class AuditFinding:
    category: str
    severity: Severity
    username: str
    message: str
    redacted_secret: str

    def __post_init__(self) -> None:
        if not self.category.strip():
            raise ValueError("category must not be empty")

        if not self.message.strip():
            raise ValueError("message must not be empty")
