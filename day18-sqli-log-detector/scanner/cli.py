import argparse
import sys

from .intelligence import SecurityAnalyzer
from .logging_utils import configure_logging
from .parser import LogParser
from .reporting import ReportWriter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Day 18 SQL Injection Log Detection Engine"
        )
    )

    parser.add_argument(
        "--input",
        default="input/mock_access.log",
        help="Access log file to analyze.",
    )

    parser.add_argument(
        "--json",
        default="output/reports/day18_sqli.json",
        help="JSON report output path.",
    )

    parser.add_argument(
        "--text",
        default="output/reports/day18_sqli.txt",
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
        verbose=args.verbose
    )

    logger.info(
        "Day 18 SQLi detection engine starting"
    )

    try:
        with open(
            args.input,
            encoding="utf-8",
        ) as handle:
            lines = handle.readlines()

    except FileNotFoundError:
        print(
            f"[!] Input file not found: {args.input}",
            file=sys.stderr,
        )
        logger.error(
            "Input file not found: %s",
            args.input,
        )
        return 2

    parser = LogParser()
    analyzer = SecurityAnalyzer()
    writer = ReportWriter()

    findings = []
    parsed_entries = 0

    for line_number, line in enumerate(
        lines,
        start=1,
    ):
        if not line.strip():
            continue

        try:
            entry = parser.parse_line(line)
            parsed_entries += 1

        except ValueError as exc:
            logger.warning(
                "Skipping malformed line %d: %s",
                line_number,
                exc,
            )
            continue

        finding = analyzer.analyze(entry)

        if finding:
            findings.append(finding)

    report = writer.build_report(
        input_file=args.input,
        total_entries=parsed_entries,
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

    print("=" * 60)
    print("DAY 18 - SQL INJECTION LOG DETECTION ENGINE")
    print("=" * 60)
    print()
    print(f"Input      : {args.input}")
    print(f"Entries    : {parsed_entries}")
    print(f"Detections : {len(findings)}")
    print(
        f"Critical   : "
        f"{report['statistics']['critical']}"
    )
    print(
        f"High       : "
        f"{report['statistics']['high']}"
    )
    print(
        f"Medium     : "
        f"{report['statistics']['medium']}"
    )
    print(
        f"Low        : "
        f"{report['statistics']['low']}"
    )
    print()
    print("REPORTS")
    print("-" * 60)
    print(f"JSON       : {args.json}")
    print(f"TXT        : {args.text}")
    print()

    logger.info(
        "Analysis complete: entries=%d findings=%d",
        parsed_entries,
        len(findings),
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
