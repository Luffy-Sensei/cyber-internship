import ipaddress


class ValidationError(ValueError):
    """Raised when scanner input fails validation."""


def validate_host(host: str) -> str:
    """Validate an IPv4 address for the controlled lab scanner."""

    host = host.strip()

    if not host:
        raise ValidationError("Host cannot be empty.")

    try:
        ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError as exc:
        raise ValidationError(
            f"Invalid IPv4 address: {host}"
        ) from exc

    return host


def validate_ports(ports: list[int]) -> tuple[int, ...]:
    """Validate and normalize TCP ports."""

    if not ports:
        raise ValidationError("At least one port is required.")

    normalized = []

    for port in ports:
        if not 1 <= port <= 65535:
            raise ValidationError(
                f"Invalid TCP port: {port}. "
                "Valid range is 1-65535."
            )

        normalized.append(port)

    return tuple(dict.fromkeys(normalized))


def validate_timeout(timeout: float) -> float:
    """Validate socket timeout."""

    if timeout <= 0:
        raise ValidationError(
            "Timeout must be greater than zero."
        )

    if timeout > 60:
        raise ValidationError(
            "Timeout cannot exceed 60 seconds."
        )

    return timeout


def validate_lab_scope(host: str) -> str:
    """
    Restrict Phase 2 scanning to localhost.

    This keeps the current development phase focused
    on controlled local infrastructure.
    """

    host = validate_host(host)

    allowed_hosts = {
        "127.0.0.1",
    }

    if host not in allowed_hosts:
        raise ValidationError(
            "Phase 2 is restricted to 127.0.0.1."
        )

    return host
