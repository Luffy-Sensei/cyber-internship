from .models import (
    RiskLevel,
    SecurityFinding,
    ServiceResult,
)


class RiskEngine:
    """Classify service exposure for authorized lab environments."""

    def analyze(
        self,
        result: ServiceResult,
    ) -> SecurityFinding:

        if result.state.value != "OPEN":
            return SecurityFinding(
                host=result.host,
                port=result.port,
                service=result.service,
                category=result.category,
                risk=RiskLevel.NONE,
                title="No exposed service detected",
                description=(
                    "The TCP endpoint did not accept "
                    "a connection during the scan."
                ),
                recommendation=(
                    "No immediate action is required "
                    "for this endpoint."
                ),
            )

        if result.category == "DATABASE":
            return SecurityFinding(
                host=result.host,
                port=result.port,
                service=result.service,
                category=result.category,
                risk=RiskLevel.HIGH,
                title="Database service exposed",
                description=(
                    f"{result.service} is accepting TCP "
                    f"connections on port {result.port}."
                ),
                recommendation=(
                    "Verify that database exposure is "
                    "intentional and restrict access "
                    "to trusted hosts or networks."
                ),
            )

        if result.category == "REMOTE_ADMINISTRATION":
            return SecurityFinding(
                host=result.host,
                port=result.port,
                service=result.service,
                category=result.category,
                risk=RiskLevel.MEDIUM,
                title="Remote administration service exposed",
                description=(
                    f"{result.service} is accepting TCP "
                    f"connections on port {result.port}."
                ),
                recommendation=(
                    "Verify that remote administration "
                    "access is required and protected "
                    "with appropriate authentication "
                    "and network controls."
                ),
            )

        if result.category == "WEB":
            return SecurityFinding(
                host=result.host,
                port=result.port,
                service=result.service,
                category=result.category,
                risk=RiskLevel.LOW,
                title="Web service exposed",
                description=(
                    f"{result.service} is accepting TCP "
                    f"connections on port {result.port}."
                ),
                recommendation=(
                    "Verify that the web service is "
                    "intentional and apply appropriate "
                    "application and transport security."
                ),
            )

        return SecurityFinding(
            host=result.host,
            port=result.port,
            service=result.service,
            category=result.category,
            risk=RiskLevel.MEDIUM,
            title="Unknown service exposed",
            description=(
                f"An unidentified service is accepting "
                f"TCP connections on port {result.port}."
            ),
            recommendation=(
                "Identify the service and verify that "
                "its exposure is intentional."
            ),
        )

    def analyze_many(
        self,
        results: list[ServiceResult],
    ) -> list[SecurityFinding]:

        return [
            self.analyze(result)
            for result in results
        ]