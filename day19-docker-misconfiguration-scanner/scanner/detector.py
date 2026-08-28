from dataclasses import dataclass

from .models import DockerfileDocument


@dataclass(frozen=True)
class SecurityFinding:
    rule_id: str
    severity: str
    line_number: int | None
    message: str
    recommendation: str


class SecurityDetector:
    """Detect security misconfigurations in Dockerfiles."""

    def analyze(
        self,
        document: DockerfileDocument,
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        has_explicit_user = False

        for instruction in document.instructions:
            directive = instruction.directive.value.upper()
            arguments = instruction.arguments.strip()

            if directive == "USER":
                has_explicit_user = True

            if directive == "FROM":
                image = arguments.split()[0]

                if image.lower() == "latest" or image.lower().endswith(
                    ":latest"
                ):
                    findings.append(
                        SecurityFinding(
                            rule_id="LATEST_TAG",
                            severity="MEDIUM",
                            line_number=instruction.line_number,
                            message=(
                                "Base image uses the unpinned 'latest' tag."
                            ),
                            recommendation=(
                                "Pin the base image to a specific version "
                                "or immutable digest."
                            ),
                        )
                    )

            if directive == "EXPOSE":
                ports = arguments.split()

                for port in ports:
                    port_number = port.split("/")[0]

                    if port_number == "22":
                        findings.append(
                            SecurityFinding(
                                rule_id="SSH_EXPOSED",
                                severity="CRITICAL",
                                line_number=instruction.line_number,
                                message=(
                                    "Dockerfile exposes SSH on TCP port 22."
                                ),
                                recommendation=(
                                    "Remove SSH exposure unless it is "
                                    "explicitly required."
                                ),
                            )
                        )
                        break

        if not has_explicit_user:
            findings.append(
                SecurityFinding(
                    rule_id="MISSING_USER",
                    severity="HIGH",
                    line_number=None,
                    message=(
                        "Dockerfile does not define an explicit USER."
                    ),
                    recommendation=(
                        "Run the application as a dedicated "
                        "non-privileged user."
                    ),
                )
            )

        return findings
