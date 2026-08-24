#!/usr/bin/env python3

"""
SE Chain Simulator - Logging

Centralized logging configuration for the application.

Design goals:
- Console logging for operator-facing output.
- File logging for full diagnostic evidence.
- Per-run correlation through run_id.
- Module identification through Python's native LogRecord.module.
- UTC timestamps for consistent event correlation.
- Exception tracebacks preserved in log files but hidden from console output.
- Safe reuse of the logger within a single process.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


LOGGER_NAME = "se_chain"

LOG_FORMAT = (
    "%(asctime)s | "
    "%(levelname)-8s | "
    "run=%(run_id)s | "
    "module=%(module)s | "
    "%(message)s"
)

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class RunContextFilter(logging.Filter):
    """
    Inject the current run ID into every log record.
    """

    def __init__(self, run_id: Optional[str] = None) -> None:
        super().__init__()
        self.run_id = run_id or "-"

    def set_run_id(self, run_id: Optional[str]) -> None:
        """
        Update the active run ID.
        """

        self.run_id = run_id or "-"

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Inject run context without overwriting native LogRecord fields.
        """

        record.run_id = self.run_id
        return True


class UTCFormatter(logging.Formatter):
    """
    Formatter that renders timestamps in UTC.
    """

    converter = staticmethod(
        lambda timestamp: datetime.fromtimestamp(
            timestamp,
            tz=timezone.utc,
        ).timetuple()
    )


class ConsoleFormatter(UTCFormatter):
    """
    Console formatter that suppresses exception tracebacks.

    The original exception information is restored after formatting,
    allowing the file handler to preserve the complete traceback.
    """

    def format(self, record: logging.LogRecord) -> str:
        original_exc_info = record.exc_info
        original_exc_text = record.exc_text

        record.exc_info = None
        record.exc_text = None

        try:
            return super().format(record)
        finally:
            record.exc_info = original_exc_info
            record.exc_text = original_exc_text


class LoggerManager:
    """
    Configure and manage application logging.
    """

    def __init__(
        self,
        log_directory: Path,
        run_id: Optional[str] = None,
    ) -> None:
        self.log_directory = Path(log_directory)
        self.run_id = run_id

        self.logger = logging.getLogger(LOGGER_NAME)

        self.context_filter = RunContextFilter(
            run_id=self.run_id,
        )

        self._configure()

    def _configure(self) -> None:
        """
        Configure console and file logging.
        """

        self.log_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.logger.setLevel(logging.DEBUG)

        # ---------------------------------------------------------------
        # Logger already configured
        # ---------------------------------------------------------------

        if self.logger.handlers:
            self._update_run_context()
            return

        # ---------------------------------------------------------------
        # Console handler
        # ---------------------------------------------------------------

        console_formatter = ConsoleFormatter(
            fmt=LOG_FORMAT,
            datefmt=DATE_FORMAT,
        )

        console_handler = logging.StreamHandler()

        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(console_formatter)
        console_handler.addFilter(self.context_filter)

        # ---------------------------------------------------------------
        # File handler
        # ---------------------------------------------------------------

        file_formatter = UTCFormatter(
            fmt=LOG_FORMAT,
            datefmt=DATE_FORMAT,
        )

        log_file = self.log_directory / "se_chain.log"

        file_handler = logging.FileHandler(
            log_file,
            encoding="utf-8",
        )

        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(file_formatter)
        file_handler.addFilter(self.context_filter)

        # ---------------------------------------------------------------
        # Register handlers
        # ---------------------------------------------------------------

        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

        # Prevent propagation to the root logger and duplicate output.
        self.logger.propagate = False

    def _update_run_context(self) -> None:
        """
        Update run context for an already-configured logger.
        """

        for handler in self.logger.handlers:
            for existing_filter in handler.filters:
                if isinstance(existing_filter, RunContextFilter):
                    existing_filter.set_run_id(self.run_id)

    def get_logger(self) -> logging.Logger:
        """
        Return the configured application logger.
        """

        return self.logger