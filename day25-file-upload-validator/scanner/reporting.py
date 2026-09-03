from __future__ import annotations

import json
from pathlib import Path

from scanner.logging import ValidationEvent


class ReportWriter:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = Path(output_dir)

    def build_summary(self, events: list[ValidationEvent]) -> dict:
        accepted = sum(
            event.action == "ACCEPT"
            for event in events
        )
        rejected = sum(
            event.action == "REJECT"
            for event in events
        )
        stored = sum(
            event.stored
            for event in events
        )

        return {
            "total_events": len(events),
            "accepted": accepted,
            "rejected": rejected,
            "stored": stored,
            "not_stored": len(events) - stored,
        }

    def write_json(
        self,
        events: list[ValidationEvent],
        filename: str = "day25-report.json",
    ) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)

        report = {
            "report": "DAY 25 FILE UPLOAD SECURITY REPORT",
            "summary": self.build_summary(events),
            "events": [
                {
                    "timestamp": event.timestamp,
                    "filename": event.filename,
                    "action": event.action,
                    "status": event.status,
                    "reason": event.reason,
                    "detected_type": event.detected_type,
                    "size_bytes": event.size_bytes,
                    "stored": event.stored,
                    "storage_name": event.storage_name,
                    "storage_class": event.storage_class,
                }
                for event in events
            ],
        }

        output_path = self.output_dir / filename
        output_path.write_text(
            json.dumps(report, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        return output_path

    def write_text(
        self,
        events: list[ValidationEvent],
        filename: str = "day25-report.txt",
    ) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)

        summary = self.build_summary(events)

        lines = [
            "DAY 25 FILE UPLOAD SECURITY REPORT",
            "=" * 40,
            "",
            "SUMMARY",
            "-------",
            f"Total events : {summary['total_events']}",
            f"Accepted     : {summary['accepted']}",
            f"Rejected     : {summary['rejected']}",
            f"Stored       : {summary['stored']}",
            f"Not stored   : {summary['not_stored']}",
            "",
            "VALIDATION EVENTS",
            "------------------",
        ]

        for index, event in enumerate(events, start=1):
            lines.extend(
                [
                    "",
                    f"Event #{index}",
                    f"Filename       : {event.filename}",
                    f"Action         : {event.action}",
                    f"Status         : {event.status}",
                    f"Detected type  : {event.detected_type}",
                    f"Size           : {event.size_bytes} bytes",
                    f"Stored         : {event.stored}",
                    f"Storage name   : {event.storage_name}",
                    f"Storage class  : {event.storage_class}",
                    f"Reason         : {event.reason}",
                    f"Timestamp      : {event.timestamp}",
                ]
            )

        output_path = self.output_dir / filename
        output_path.write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
        )

        return output_path
