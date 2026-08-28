import argparse
import sys

from .detector import SecurityDetector
from .logging_utils import configure_logging
from .parser import DockerfileParser
from .reporting import ReportWriter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Day 19 Docker Container Misconfiguration Scanner"
    )

    parser.add_argument(
        "--input",
        default="input/Dockerfile.test",
        help="Dockerfile to analyze.",
    )

    parser.add_argument(
        "--json",
        default="output/reports/day19_docker.json",
        help="JSON report output path.",
    )

    parser.add_argument(
        "--text",
        default="output/reports/day19_docker.txt",
        help="TXT report output path.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )

    return parser


def main() -> int:
    args = build_parser().parse_args()

    logger = configure_logging(
        verbose=args.verbose,
    )

    logger.info(
        "Day 19 Docker security scanner starting"
    )

    try:
        parser = DockerfileParser()

        document = parser.parse_file(
            args.input
        )

        detector = SecurityDetector()

        findings = detector.analyze(
            document
        )

        writer = ReportWriter()

        report = writer.build_report(
            input_file=args.input,
            findings=findings,
        )

        writer.write_json(
            report,
            args.json,
        )

        writer.write_text(
            report,
            args.text,
        )

    except FileNotFoundError:
        logger.error(
            "Input Dockerfile not found: %s",
            args.input,
        )
        return 1

    except Exception as exc:
        logger.exception(
            "Scan failed: %s",
            exc,
        )
        return 1

    statistics = report["statistics"]

    print()
    print("=" * 60)
    print("DAY 19 - DOCKER MISCONFIGURATION SCANNER")
    print("=" * 60)
    print()

    print(f"Input      : {args.input}")
    print(f"Instructions: {len(document.instructions)}")
    print(f"Findings   : {statistics['findings']}")
    print(f"Critical   : {statistics['critical']}")
    print(f"High       : {statistics['high']}")
    print(f"Medium     : {statistics['medium']}")
    print(f"Low        : {statistics['low']}")

    print()
    print("REPORTS")
    print("-" * 60)
    print(f"JSON       : {args.json}")
    print(f"TXT        : {args.text}")

    logger.info(
        "Analysis complete: instructions=%d findings=%d",
        len(document.instructions),
        len(findings),
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
