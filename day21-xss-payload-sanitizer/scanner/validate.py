from __future__ import annotations

import argparse
import logging
import sys

from .validation_runner import run_validation


LOGGER = logging.getLogger("day21")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Day 21 adversarial XSS sanitizer validation. "
            "Use for defensive security testing."
        )
    )

    parser.add_argument(
        "--input",
        default="input/adversarial_payloads.txt",
        help="Path to adversarial payload corpus.",
    )

    parser.add_argument(
        "--json",
        default="output/reports/day21_adversarial_validation.json",
        help="JSON evidence report path.",
    )

    parser.add_argument(
        "--log",
        default="output/logs/day21_validation.log",
        help="Validation log path.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose console logging.",
    )

    return parser


def configure_logging(log_path: str, verbose: bool) -> None:
    """Configure console and file logging."""

    level = logging.DEBUG if verbose else logging.INFO

    log_file = logging.FileHandler(
        log_path,
        encoding="utf-8",
    )

    console = logging.StreamHandler()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    log_file.setFormatter(formatter)
    console.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(level)

    logger.handlers.clear()
    logger.addHandler(log_file)
    logger.addHandler(console)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        configure_logging(args.log, args.verbose)

        LOGGER.info("Day 21 adversarial validation starting")
        LOGGER.info("Payload corpus: %s", args.input)

        report = run_validation(
            payload_path=args.input,
            report_path=args.json,
        )

        print()
        print("=" * 60)
        print("DAY 21 - XSS ADVERSARIAL VALIDATION")
        print("=" * 60)
        print()
        print(f"Payloads : {report['payload_count']}")
        print(f"Passed   : {report['passed']}")
        print(f"Failed   : {report['failed']}")
        print(f"Status   : {'PASS' if report['all_passed'] else 'FAIL'}")
        print()
        print("EVIDENCE")
        print("-" * 60)
        print(f"JSON     : {args.json}")
        print(f"Log      : {args.log}")
        print()

        return 0 if report["all_passed"] else 1

    except (FileNotFoundError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    except KeyboardInterrupt:
        LOGGER.warning("Validation interrupted by user")
        return 130


if __name__ == "__main__":
    sys.exit(main())
