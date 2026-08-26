from scanner.models import (
    PortState,
    RiskLevel,
    SecurityFinding,
    ServiceResult,
)

from scanner.topology import TopologyBuilder


def test_topology_contains_open_service():
    service_results = [
        ServiceResult(
            host="127.0.0.1",
            port=80,
            protocol="TCP",
            state=PortState.OPEN,
            service="HTTP",
            category="WEB",
            confidence="HIGH",
            detection_method="HTTP_PROBE",
            latency_ms=1.0,
            evidence="HTTP/1.1 200 OK",
        )
    ]

    findings = [
        SecurityFinding(
            host="127.0.0.1",
            port=80,
            service="HTTP",
            category="WEB",
            risk=RiskLevel.LOW,
            title="Web service exposed",
            description="HTTP is accepting TCP connections.",
            recommendation="Verify exposure is intentional.",
        )
    ]

    topology = TopologyBuilder().build(
        host="127.0.0.1",
        service_results=service_results,
        findings=findings,
    )

    assert len(topology["nodes"]) == 1
    assert len(topology["edges"]) == 1

    edge = topology["edges"][0]

    assert edge["port"] == 80
    assert edge["service"] == "HTTP"
    assert edge["risk"] == "LOW"

def test_closed_service_is_not_topology_edge():
    service_results = [
        ServiceResult(
            host="127.0.0.1",
            port=5432,
            protocol="TCP",
            state=PortState.CLOSED,
            service="PostgreSQL",
            category="DATABASE",
            confidence="NONE",
            detection_method="NO_SERVICE_IDENTIFICATION",
        )
    ]

    topology = TopologyBuilder().build(
        host="127.0.0.1",
        service_results=service_results,
        findings=[],
    )

    assert topology["edges"] == []    
