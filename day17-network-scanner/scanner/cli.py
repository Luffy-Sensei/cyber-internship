import argparse
from pathlib import Path

from .config import (
    DEFAULT_HOST,
    DEFAULT_PORTS,
    DEFAULT_TIMEOUT,
    ScannerConfig,
)
from .logging_config import configure_logging
from .safety import (
    ValidationError,
    validate_lab_scope,
    validate_ports,
    validate_timeout,
)
from .scanner import TCPScanner
from .services import ServiceMapper
from .risk import RiskEngine
from .reporting import ReportWriter
from .report_schema import validate_report


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Day 17 - Local TCP Network Scanner"
        )
    )

    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=(
            "Authorized lab target "
            "(default: 127.0.0.1)"
        ),
    )

    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_PORTS,
        help="TCP ports to scan",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Connection timeout in seconds",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    try:
        host = validate_lab_scope(
            args.host
        )

        ports = validate_ports(
            args.ports
        )

        timeout = validate_timeout(
            args.timeout
        )

    except ValidationError as exc:
        print(f"[!] Validation error: {exc}")
        return 2

    config = ScannerConfig(
        host=host,
        ports=ports,
        timeout=timeout,
    )

    logger = configure_logging(
        Path("output/logs"),
        verbose=args.verbose,
    )

    logger.info(
        "Configuration loaded: %s",
        config,
    )

    print("=" * 60)
    print("DAY 17 - LOCAL NETWORK PORT SCANNER")
    print("=" * 60)
    print(f"Target : {config.host}")
    print(f"Ports  : {list(config.ports)}")
    print(f"Timeout: {config.timeout}s")
    print()

    scanner = TCPScanner(
        timeout=config.timeout,
        logger=logger,
    )

    results = scanner.scan_ports(
        config.host,
        config.ports,
    )

    service_mapper = ServiceMapper()

    service_results = [
        service_mapper.verify(
            result,
            timeout=config.timeout,
        )
        for result in results
    ]

    risk_engine = RiskEngine()

    findings = risk_engine.analyze_many(
        service_results
    )

    report_writer = ReportWriter(
        Path("output/reports")
    )

    report = report_writer.build_report(
        host=config.host,
        ports=config.ports,
        timeout=config.timeout,
        scan_results=results,
        service_results=service_results,
        findings=findings,
    )

    validate_report(report)
    
    json_path = report_writer.write_json(report)
    text_path = report_writer.write_text(report)



    for result in service_results:
        latency = (
            f"{result.latency_ms:.2f} ms"
            if result.latency_ms is not None
            else "-"
        )

        print(
            f"{result.port:>5}/TCP  "
            f"{result.state.value:<8}  "
            f"{result.service:<16} "
            f"{result.category:<20} "
            f"{latency}"
        )

        if result.state.value == "OPEN":
            print(
                f"       Detection: "
                f"{result.detection_method} "
                f"(confidence: {result.confidence})"
            )

            if result.evidence:
                print(
                    f"       Evidence: "
                    f"{result.evidence}"
                )

    print()
    print("=" * 60)
    print("SECURITY EXPOSURE ANALYSIS")
    print("=" * 60)
    print()

    for finding in findings:
        if finding.risk.value == "NONE":
            continue

        print(
            f"[{finding.risk.value}] "
            f"{finding.port}/TCP - "
            f"{finding.title}"
        )

        print(
            f"       Service: {finding.service}"
        )

        print(
            f"       Category: {finding.category}"
        )

        print(
            f"       Description: "
            f"{finding.description}"
        )

        print(
            f"       Recommendation: "
            f"{finding.recommendation}"
        )

        print()

    risk_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        if finding.risk.value in risk_counts:
            risk_counts[finding.risk.value] += 1

    print("=" * 60)
    print("RISK SUMMARY")
    print("=" * 60)

    for level, count in risk_counts.items():
        print(f"{level:<10}: {count}")    

    print()
    print("=" * 60)
    print("REPORTS")
    print("=" * 60)
    print()
    print(f"JSON: {json_path}")
    print(f"TEXT: {text_path}")

if __name__ == "__main__":
    raise SystemExit(main())
