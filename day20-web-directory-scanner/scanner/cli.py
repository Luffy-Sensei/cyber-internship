from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .analyzer import WebDirectoryAnalyzer
from .client import HTTPClient
from .config import build_config
from .reporting import ScanReporter
from .wordlist import load_wordlist


LOGGER = logging.getLogger("day20")


def configure_logging(
    verbose: bool = False,
    log_path: str = "output/logs/day20_scan.log",
) -> None:
    level = logging.DEBUG if verbose else logging.INFO

    log_file = Path(log_path)
    log_file.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Prevent duplicate handlers if run_scan() is called more than once
    # during the same Python process.
    root_logger.handlers.clear()

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(
        log_file,
        mode="w",
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Day 20 web directory discovery scanner. "
            "Use only against authorized targets."
        )
    )

    parser.add_argument(
        "--url",
        required=True,
        help="Base HTTP/HTTPS URL to scan.",
    )

    parser.add_argument(
        "--wordlist",
        required=True,
        help="Path to newline-separated wordlist.",
    )

    parser.add_argument(
        "--json",
        default="output/reports/day20_web.json",
        help="JSON report output path.",
    )

    parser.add_argument(
        "--text",
        default="output/reports/day20_web.txt",
        help="TXT report output path.",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="HTTP request timeout in seconds.",
    )

    parser.add_argument(
        "--follow-redirects",
        action="store_true",
        help="Follow HTTP redirects.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )

    return parser


def run_scan(args: argparse.Namespace) -> int:
    configure_logging(verbose=args.verbose)

    LOGGER.info("Day 20 web directory scanner starting")

    try:
        config = build_config(
            base_url=args.url,
            wordlist_path=args.wordlist,
            timeout=args.timeout,
            follow_redirects=args.follow_redirects,
        )

        wordlist = load_wordlist(config.wordlist_path)

        if not wordlist:
            raise ValueError("Wordlist contains no usable entries.")

        LOGGER.info(
            "Target=%s wordlist_entries=%d",
            config.base_url,
            len(wordlist),
        )

        client = HTTPClient(config)

        results = []

        for path in wordlist:
            LOGGER.debug("Scanning path: /%s", path)

            result = client.scan_path(path)
            results.append(result)

            if result.error:
                LOGGER.warning(
                    "Request failed for /%s: %s",
                    path,
                    result.error,
                )
            else:
                LOGGER.debug(
                    "Response /%s -> HTTP %s",
                    path,
                    result.status_code,
                )

        analyzer = WebDirectoryAnalyzer(
            target=config.base_url,
            wordlist=wordlist,
        )

        report = analyzer.analyze(results)

        reporter = ScanReporter(
            target=config.base_url,
            wordlist_size=len(wordlist),
            requests_sent=len(wordlist),
        )

        # Preserve the analyzer-generated findings and metadata.
        report = reporter.build_report(report["findings"])

        reporter.write_json(report, args.json)
        reporter.write_text(report, args.text)

        summary = report["summary"]

        print()
        print("=" * 60)
        print("DAY 20 - WEB DIRECTORY DISCOVERY SCANNER")
        print("=" * 60)
        print()
        print(f"Target          : {config.base_url}")
        print(f"Wordlist        : {len(wordlist)} entries")
        print(f"Requests        : {len(wordlist)}")
        print(f"Findings        : {summary['total_findings']}")
        print(f"Critical        : {summary['critical']}")
        print(f"High            : {summary['high']}")
        print(f"Medium          : {summary['medium']}")
        print(f"Low             : {summary['low']}")
        print()
        print("REPORTS")
        print("-" * 60)
        print(f"JSON            : {args.json}")
        print(f"TXT             : {args.text}")
        print()

        LOGGER.info(
            "Scan complete: requests=%d findings=%d",
            len(wordlist),
            summary["total_findings"],
        )

        return 0

    except FileNotFoundError as exc:
        LOGGER.error("%s", exc)
        return 2

    except (ValueError, OSError) as exc:
        LOGGER.error("%s", exc)
        return 2

    except KeyboardInterrupt:
        LOGGER.warning("Scan interrupted by user")
        return 130


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run_scan(args)


if __name__ == "__main__":
    sys.exit(main())
