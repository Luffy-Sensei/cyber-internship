from dataclasses import dataclass
from typing import Optional

from .models import PathResult
from .rules import (
    RULE_DIRECTORY_200,
    RULE_DIRECTORY_403,
    RULE_DIRECTORY_5XX,
    RULE_DIRECTORY_REDIRECT,
    RULE_SENSITIVE_EXPOSURE,
    is_sensitive_path,
)


@dataclass(frozen=True)
class SecurityFinding:
    rule_id: str
    path: str
    url: str
    status_code: Optional[int]
    message: str
    evidence: str


class SecurityDetector:
    def analyze(self, result: PathResult) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        if result.error:
            return findings

        status = result.status_code

        if status == 200:
            findings.append(
                SecurityFinding(
                    rule_id=RULE_DIRECTORY_200,
                    path=result.path,
                    url=result.url,
                    status_code=status,
                    message="Endpoint is accessible.",
                    evidence=(
                        f"HTTP {status}; "
                        f"response length={result.response_length}"
                    ),
                )
            )

            if is_sensitive_path(result.path):
                findings.append(
                    SecurityFinding(
                        rule_id=RULE_SENSITIVE_EXPOSURE,
                        path=result.path,
                        url=result.url,
                        status_code=status,
                        message=(
                            "Sensitive path is publicly accessible."
                        ),
                        evidence=(
                            f"HTTP {status}; "
                            f"response length={result.response_length}"
                        ),
                    )
                )

        elif status == 403:
            findings.append(
                SecurityFinding(
                    rule_id=RULE_DIRECTORY_403,
                    path=result.path,
                    url=result.url,
                    status_code=status,
                    message="Endpoint exists but access is forbidden.",
                    evidence=f"HTTP {status}",
                )
            )

        elif status is not None and 300 <= status < 400:
            findings.append(
                SecurityFinding(
                    rule_id=RULE_DIRECTORY_REDIRECT,
                    path=result.path,
                    url=result.url,
                    status_code=status,
                    message="Endpoint redirects to another location.",
                    evidence=(
                        f"HTTP {status}; "
                        f"Location={result.location}"
                    ),
                )
            )

        elif status is not None and 500 <= status < 600:
            findings.append(
                SecurityFinding(
                    rule_id=RULE_DIRECTORY_5XX,
                    path=result.path,
                    url=result.url,
                    status_code=status,
                    message="Server returned a 5xx response.",
                    evidence=f"HTTP {status}",
                )
            )

        return findings
