#!/usr/bin/env python3

"""
SE Chain Simulator - Run State Persistence

Persists completed simulation contexts to disk so that CLI commands
can access the latest run across separate Python processes.
"""

from __future__ import annotations

import json
from dataclasses import asdict, fields
from datetime import datetime
from pathlib import Path
from typing import Any

from se_chain.config import RUNS_DIR
from se_chain.exceptions import ReportingError
from se_chain.models import (
    ChainContext,
    ChainStatus,
    IRAction,
    ModuleResult,
    RunMetadata,
    SimulationEvent,
)


class RunStore:
    """
    Persistent storage for simulator run state.

    Each run is stored as:

        output/runs/<run_id>.json

    The latest run is determined from the run timestamps rather
    than from a fragile global variable.
    """

    def __init__(self, directory: Path = RUNS_DIR) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save(self, context: ChainContext) -> Path:
        """
        Persist a simulation context to disk.

        Returns:
            Path to the saved run-state file.
        """

        if context is None:
            raise ReportingError("Cannot persist an empty simulation context")

        run_id = context.metadata.run_id

        if not run_id:
            raise ReportingError("Cannot persist simulation without a run ID")

        path = self.directory / f"{run_id}.json"

        payload = self._context_to_dict(context)

        try:
            self._atomic_write(path, payload)
        except OSError as exc:
            raise ReportingError(
                f"Unable to save run state: {exc}"
            ) from exc

        return path

    def load(self, run_id: str) -> ChainContext:
        """
        Load a specific simulation context.
        """

        if not run_id:
            raise ReportingError("Run ID is required")

        path = self.directory / f"{run_id}.json"

        if not path.exists():
            raise ReportingError(
                f"Run state not found: {path}"
            )

        try:
            with path.open("r", encoding="utf-8") as file:
                payload = json.load(file)

        except json.JSONDecodeError as exc:
            raise ReportingError(
                f"Invalid run-state JSON: {path}"
            ) from exc

        except OSError as exc:
            raise ReportingError(
                f"Unable to read run state: {exc}"
            ) from exc

        return self._context_from_dict(payload)

    def load_latest(self) -> ChainContext | None:
        """
        Load the most recent persisted simulation.

        Returns:
            Latest ChainContext, or None when no runs exist.
        """

        files = list(self.directory.glob("*.json"))

        if not files:
            return None

        latest_path = max(
            files,
            key=lambda path: path.stat().st_mtime,
        )

        return self.load(latest_path.stem)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    @staticmethod
    def _context_to_dict(context: ChainContext) -> dict[str, Any]:
        """
        Convert ChainContext into JSON-compatible data.
        """

        return {
            "metadata": RunStore._metadata_to_dict(context.metadata),
            "authorized": context.authorized,
            "target_config": context.target_config,
            "module_results": {
                name: RunStore._module_result_to_dict(result)
                for name, result in context.module_results.items()
            },
            "events": [
                RunStore._event_to_dict(event)
                for event in context.events
            ],
            "ir_actions": [
                RunStore._ir_action_to_dict(action)
                for action in context.ir_actions
            ],
            "data": context.data,
            "errors": context.errors,
        }

    @staticmethod
    def _metadata_to_dict(metadata: RunMetadata) -> dict[str, Any]:
        data = asdict(metadata)

        data["started_at"] = RunStore._datetime_to_string(
            metadata.started_at
        )

        data["completed_at"] = RunStore._datetime_to_string(
            metadata.completed_at
        )

        return data

    @staticmethod
    def _module_result_to_dict(
        result: ModuleResult,
    ) -> dict[str, Any]:

        data = asdict(result)

        data["started_at"] = RunStore._datetime_to_string(
            result.started_at
        )

        data["completed_at"] = RunStore._datetime_to_string(
            result.completed_at
        )

        return data

    @staticmethod
    def _event_to_dict(
        event: SimulationEvent,
    ) -> dict[str, Any]:

        data = asdict(event)

        data["timestamp"] = RunStore._datetime_to_string(
            event.timestamp
        )

        return data

    @staticmethod
    def _ir_action_to_dict(
        action: IRAction,
    ) -> dict[str, Any]:

        data = asdict(action)

        data["timestamp"] = RunStore._datetime_to_string(
            action.timestamp
        )

        return data

    # ------------------------------------------------------------------
    # Deserialization
    # ------------------------------------------------------------------

    @staticmethod
    def _context_from_dict(
        payload: dict[str, Any],
    ) -> ChainContext:

        metadata_data = payload.get("metadata", {})

        metadata = RunMetadata(
            run_id=metadata_data.get("run_id", ""),
            target=metadata_data.get("target", ""),
            mode=metadata_data.get("mode", ""),
            started_at=RunStore._string_to_datetime(
                metadata_data.get("started_at")
            ),
            completed_at=RunStore._string_to_datetime(
                metadata_data.get("completed_at")
            ),
            status=metadata_data.get(
                "status",
                ChainStatus.INITIALIZED,
            ),
            application=metadata_data.get(
                "application",
                "SE Chain Simulator",
            ),
            version=metadata_data.get(
                "version",
                "1.0.0",
            ),
        )

        module_results: dict[str, ModuleResult] = {}

        for name, raw in payload.get(
            "module_results",
            {},
        ).items():

            result = ModuleResult(
                module=raw.get("module", name),
                success=raw.get("success", False),
                message=raw.get("message", ""),
                status=raw.get("status", "completed"),
                data=raw.get("data", {}),
                warnings=raw.get("warnings", []),
                errors=raw.get("errors", []),
                started_at=RunStore._string_to_datetime(
                    raw.get("started_at")
                ),
                completed_at=RunStore._string_to_datetime(
                    raw.get("completed_at")
                ),
            )

            module_results[name] = result

        events = [
            SimulationEvent(
                event_type=raw.get("event_type", ""),
                stage=raw.get("stage", ""),
                description=raw.get("description", ""),
                severity=raw.get("severity", "info"),
                timestamp=RunStore._string_to_datetime(
                    raw.get("timestamp")
                ),
                metadata=raw.get("metadata", {}),
                simulated=raw.get("simulated", True),
            )
            for raw in payload.get("events", [])
        ]

        ir_actions = [
            IRAction(
                action_type=raw.get("action_type", ""),
                description=raw.get("description", ""),
                status=raw.get("status", "simulated"),
                timestamp=RunStore._string_to_datetime(
                    raw.get("timestamp")
                ),
                metadata=raw.get("metadata", {}),
            )
            for raw in payload.get("ir_actions", [])
        ]

        return ChainContext(
            metadata=metadata,
            authorized=payload.get("authorized", False),
            target_config=payload.get("target_config", {}),
            module_results=module_results,
            events=events,
            ir_actions=ir_actions,
            data=payload.get("data", {}),
            errors=payload.get("errors", []),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _datetime_to_string(
        value: datetime | None,
    ) -> str | None:

        if value is None:
            return None

        return value.isoformat()

    @staticmethod
    def _string_to_datetime(
        value: str | None,
    ) -> datetime | None:

        if value is None:
            return None

        return datetime.fromisoformat(value)

    @staticmethod
    def _atomic_write(
        path: Path,
        payload: dict[str, Any],
    ) -> None:
        """
        Write JSON safely using a temporary file followed by replace.
        """

        temporary_path = path.with_suffix(".tmp")

        with temporary_path.open(
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                payload,
                file,
                indent=2,
                ensure_ascii=False,
            )

            file.write("\n")

        temporary_path.replace(path)
