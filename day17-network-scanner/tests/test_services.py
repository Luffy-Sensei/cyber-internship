from scanner.models import PortState, ScanResult
from scanner.services import ServiceMapper


def test_http_port_mapping():
    result = ScanResult(
        host="127.0.0.1",
        port=80,
        protocol="TCP",
        state=PortState.OPEN,
    )

    mapped = ServiceMapper().identify(result)

    assert mapped.service == "HTTP"
    assert mapped.category == "WEB"
    assert mapped.confidence == "LOW"
    assert mapped.detection_method == "PORT_HINT"


def test_postgresql_port_mapping():
    result = ScanResult(
        host="127.0.0.1",
        port=5432,
        protocol="TCP",
        state=PortState.CLOSED,
    )

    mapped = ServiceMapper().identify(result)

    assert mapped.service == "PostgreSQL"
    assert mapped.category == "DATABASE"
    assert mapped.confidence == "NONE"


def test_unknown_port():
    result = ScanResult(
        host="127.0.0.1",
        port=55555,
        protocol="TCP",
        state=PortState.OPEN,
    )

    mapped = ServiceMapper().identify(result)

    assert mapped.service == "UNKNOWN"
    assert mapped.category == "UNKNOWN"
def test_http_probe_localhost():
    mapper = ServiceMapper()

    success, evidence = mapper.probe_http(
        "127.0.0.1",
        80,
    )

    assert success is True
    assert evidence.startswith("HTTP/")


def test_closed_port_does_not_get_verified():
    result = ScanResult(
        host="127.0.0.1",
        port=5432,
        protocol="TCP",
        state=PortState.CLOSED,
    )

    mapped = ServiceMapper().verify(result)

    assert mapped.service == "PostgreSQL"
    assert mapped.confidence == "NONE"
    assert mapped.detection_method == (
        "NO_SERVICE_IDENTIFICATION"
    )
