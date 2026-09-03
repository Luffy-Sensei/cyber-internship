from __future__ import annotations

import argparse
from pathlib import Path

from scanner.models import UploadedFile
from scanner.pipeline import UploadSecurityPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Day 25 secure file upload validation pipeline."
    )

    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("input"),
        help="Directory containing benign/ and malicious/ fixtures.",
    )

    parser.add_argument(
        "--log",
        type=Path,
        default=Path("output/logs/upload-audit.jsonl"),
        help="JSONL audit log path.",
    )

    parser.add_argument(
        "--report-dir",
        type=Path,
        default=Path("output/reports"),
        help="Directory for generated reports.",
    )

    return parser


def discover_files(input_dir: Path) -> list[Path]:
    if not input_dir.is_dir():
        raise FileNotFoundError(
            f"Input directory does not exist: {input_dir}"
        )

    return sorted(
        path
        for path in input_dir.rglob("*")
        if path.is_file()
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    pipeline = UploadSecurityPipeline(
        log_path=args.log,
        report_dir=args.report_dir,
    )

    files = discover_files(args.input_dir)

    if not files:
        print("[!] No input files discovered.")
        return 1

    print("=" * 60)
    print("DAY 25 — FILE UPLOAD SECURITY VALIDATOR")
    print("=" * 60)
    print(f"Input directory : {args.input_dir}")
    print(f"Audit log       : {args.log}")
    print(f"Report directory: {args.report_dir}")
    print()

    for path in files:
        uploaded_file = UploadedFile(
            path=str(path),
            filename=path.name,
            size_bytes=path.stat().st_size,
        )

        result = pipeline.process(uploaded_file)

        print(
            f"[{result.action.value}] "
            f"{result.filename:<20} "
            f"{result.reason}"
        )

    json_report, text_report = pipeline.generate_reports()

    print()
    print("-" * 60)
    print(f"[+] JSON report : {json_report}")
    print(f"[+] TXT report  : {text_report}")
    print(f"[+] Audit log   : {args.log}")
    print("-" * 60)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
