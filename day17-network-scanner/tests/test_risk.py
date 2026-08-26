from scanner.models import (
    PortState,
    RiskLevel,
    ServiceResult,
)

from scanner.risk import RiskEngine


def test_closed_service_has_no_risk():
    result = ServiceResult(
        host="127.0.0.1",
        port=5432,
        protocol="TCP",
        state=PortState.CLOSED,
        service="PostgreSQL",
        category="DATABASE",
        confidence="NONE",
        detection_method="NO_SERVICE_IDENTIFICATION",
    )

    finding = RiskEngine().analyze(result)

    assert finding.risk == RiskLevel.NONE


def test_open_database_is_high_risk():
    result = ServiceResult(
        host="127.0.0.1",
        port=5432,
        protocol="TCP",
        state=PortState.OPEN,
        service="PostgreSQL",
        category="DATABASE",
        confidence="HIGH",
        detection_method="PORT_HINT",
    )

    finding = RiskEngine().analyze(result)

    assert finding.risk == RiskLevel.HIGH
    assert "Database" in finding.title


def test_open_http_is_low_risk():
    result = ServiceResult(
        host="127.0.0.1",
        port=80,
        protocol="TCP",
        state=PortState.OPEN,
        service="HTTP",
        category="WEB",
        confidence="HIGH",
        detection_method="HTTP_PROBE",
    )

    finding = RiskEngine().analyze(result)

    assert finding.risk == RiskLevel.LOW
