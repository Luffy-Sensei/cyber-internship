#!/usr/bin/env python3

"""
SE Chain Simulator - CLI

Command-line interface for the authorized social-engineering
attack-chain simulation framework.

Responsibilities:
    - argument parsing
    - interactive menu handling
    - progress/status display
    - invoking the chain engine
    - persistent run-state handling
    - report generation

Simulation logic belongs to ChainEngine and individual modules.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from se_chain.config import (
    APP_NAME,
    APP_VERSION,
    REPORTS_DIR,
    load_lab_target,
)
from se_chain.engine import ChainEngine
from se_chain.models import (
    ChainContext,
    ChainStatus,
    RunMetadata,
)
from se_chain.reporting.json_report import JSONReporter
from se_chain.reporting.text_report import TextReporter
from se_chain.run_store import RunStore


# ---------------------------------------------------------------------------
# Runtime state
# ---------------------------------------------------------------------------

_latest_context: ChainContext | None = None
_run_store = RunStore()


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_banner() -> None:
    """Display the application banner."""

    print()
    print("=" * 60)
    print(f"{APP_NAME:^60}")
    print(f"Version {APP_VERSION:^51}")
    print("=" * 60)
    print()


def print_target(target_config: dict) -> None:
    """Display the configured simulation target."""

    print(
        f"Target : "
        f"{target_config.get('target', 'unknown')}"
    )

    print(
        f"Type   : "
        f"{target_config.get('target_type', 'unknown')}"
    )

    print(
        f"Mode   : "
        f"{target_config.get('environment', 'unknown')}"
    )

    print()


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------

def create_context() -> ChainContext:
    """
    Load the authorized laboratory configuration and create
    a ChainContext for the current run.
    """

    target = load_lab_target()

    metadata = RunMetadata(
        target=target["target"],
        mode=target["environment"],
    )

    return ChainContext(
        metadata=metadata,
        authorized=target["authorized"],
        target_config=target,
    )


# ---------------------------------------------------------------------------
# Progress
# ---------------------------------------------------------------------------

def print_progress(context: ChainContext) -> None:
    """
    Display simulation progress from the stored ChainContext.

    This function does not execute simulation logic.
    """

    print("PROGRESS")
    print("-" * 60)

    if not context.module_results:
        print("No modules have executed.")
        print()
        return

    for name, result in context.module_results.items():

        symbol = "[+]" if result.success else "[!]"

        print(
            f"{symbol} "
            f"{name:<12} "
            f"{result.status:<10} "
            f"{result.message}"
        )

    print()


# ---------------------------------------------------------------------------
# Module status
# ---------------------------------------------------------------------------

def print_module_status(context: ChainContext) -> None:
    """Display module execution status and simulation metrics."""

    print("MODULE STATUS")
    print("-" * 60)

    if not context.module_results:
        print("No modules have executed.")
        print()
        return

    for name, result in context.module_results.items():

        symbol = "[+]" if result.success else "[!]"

        print(
            f"{symbol} "
            f"{name:<12} "
            f"{result.status:<10} "
            f"{result.message}"
        )

    print()

    print(
        f"Events generated : "
        f"{len(context.events)}"
    )

    print(
        f"IR actions       : "
        f"{len(context.ir_actions)}"
    )

    phish_result = context.module_results.get("phish")

    if phish_result:

        risk = phish_result.data.get(
            "risk_assessment",
            {},
        )

        if risk:

            print(
                f"Risk score       : "
                f"{risk.get('score', 0)}"
            )

            print(
                f"Risk level       : "
                f"{risk.get('level', 'UNKNOWN')}"
            )

    print()


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------

def run_all() -> ChainContext:
    """
    Execute the complete authorized simulation.

    The resulting context is:
        1. stored in memory
        2. persisted through RunStore
    """

    global _latest_context

    context = create_context()

    print_banner()
    print_target(context.target_config)

    print("Starting simulation...")
    print()

    engine = ChainEngine()

    context = engine.run(context)

    # Store current runtime state.
    _latest_context = context

    # Persist state so it survives process termination.
    try:
        _run_store.save(context)

    except Exception as exc:
        print(
            f"[!] Warning: unable to persist run state: "
            f"{exc}"
        )

    print()
    print("=" * 60)

    if context.metadata.status == ChainStatus.COMPLETED:
        print("RUN COMPLETED".center(60))

    elif context.metadata.status == ChainStatus.BLOCKED:
        print("RUN BLOCKED".center(60))

    else:
        print("RUN FAILED".center(60))

    print("=" * 60)

    print(
        f"Run ID : "
        f"{context.metadata.run_id}"
    )

    print(
        f"Status : "
        f"{context.metadata.status}"
    )

    print()

    print_module_status(context)

    return context


# ---------------------------------------------------------------------------
# Load latest context
# ---------------------------------------------------------------------------

def get_latest_context() -> ChainContext | None:
    """
    Return the latest simulation context.

    Resolution order:

        1. In-memory context
        2. Persisted RunStore state
        3. None
    """

    global _latest_context

    # ---------------------------------------------------------------
    # Runtime context
    # ---------------------------------------------------------------

    if _latest_context is not None:
        return _latest_context

    # ---------------------------------------------------------------
    # Persistent context
    # ---------------------------------------------------------------

    try:
        context = _run_store.load_latest()

    except Exception as exc:
        print()
        print(
            f"[!] Unable to load previous simulation: "
            f"{exc}"
        )
        print()
        return None

    if context is not None:
        _latest_context = context

    return context


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def show_status() -> None:
    """
    Display the latest simulation status.

    Does NOT start a new simulation.
    """

    context = get_latest_context()

    if context is None:

        print()
        print("[!] No simulation has been run yet.")
        print("    Run option 1 first.")
        print()

        return

    print()
    print("=" * 60)
    print("CURRENT SIMULATION STATUS".center(60))
    print("=" * 60)

    print(
        f"Run ID    : "
        f"{context.metadata.run_id}"
    )

    print(
        f"Target    : "
        f"{context.metadata.target}"
    )

    print(
        f"Mode      : "
        f"{context.metadata.mode}"
    )

    print(
        f"Status    : "
        f"{context.metadata.status}"
    )

    print(
        f"Authorized: "
        f"{context.authorized}"
    )

    print()

    print_progress(context)
    print_module_status(context)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def generate_reports(
    context: ChainContext,
) -> tuple[Path, Path]:
    """Generate JSON and text reports."""

    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    json_path = (
        REPORTS_DIR
        / f"{context.metadata.run_id}.json"
    )

    text_path = (
        REPORTS_DIR
        / f"{context.metadata.run_id}.txt"
    )

    json_report = JSONReporter().generate(
        context,
        json_path,
    )

    text_report = TextReporter().generate(
        context,
        text_path,
    )

    print("REPORTS GENERATED")
    print("-" * 60)

    print(
        f"JSON : "
        f"{json_report}"
    )

    print(
        f"TEXT : "
        f"{text_report}"
    )

    print()

    return json_report, text_report


def report_latest() -> bool:
    """
    Generate reports for the latest simulation.

    Returns:
        True if a simulation exists.
        False otherwise.
    """

    context = get_latest_context()

    if context is None:

        print()
        print(
            "[!] No simulation available "
            "for reporting."
        )
        print(
            "    Run option 1 first."
        )
        print()

        return False

    generate_reports(context)

    return True


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

def interactive_menu() -> int:
    """Run the interactive CLI menu."""

    while True:

        print_banner()

        try:
            target = load_lab_target()
            print_target(target)

        except Exception as exc:

            print(
                f"[!] Unable to load lab "
                f"configuration: {exc}"
            )

            return 1

        print("1. Run full simulation")
        print("2. Show status")
        print("3. Generate report")
        print("4. Exit")
        print()

        try:
            choice = input(
                "Select an option: "
            ).strip()

        except (EOFError, KeyboardInterrupt):

            print("\nExiting.")

            return 0

        print()

        # -----------------------------------------------------------
        # Run
        # -----------------------------------------------------------

        if choice == "1":

            try:
                run_all()

            except Exception as exc:

                print(
                    f"[!] Simulation failed: "
                    f"{exc}"
                )

        # -----------------------------------------------------------
        # Status
        # -----------------------------------------------------------

        elif choice == "2":

            show_status()

        # -----------------------------------------------------------
        # Report
        # -----------------------------------------------------------

        elif choice == "3":

            report_latest()

        # -----------------------------------------------------------
        # Exit
        # -----------------------------------------------------------

        elif choice == "4":

            print("Exiting.")

            return 0

        else:

            print("[!] Invalid option.")

        print()

        try:
            input(
                "Press Enter to continue..."
            )

        except (EOFError, KeyboardInterrupt):

            print()

            return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""

    parser = argparse.ArgumentParser(
        prog="se_chain.py",
        description=(
            "Authorized social-engineering "
            "attack-chain simulation framework."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {APP_VERSION}",
    )

    parser.add_argument(
        "--run-all",
        action="store_true",
        help=(
            "Run the complete authorized "
            "simulation chain."
        ),
    )

    parser.add_argument(
        "--report",
        action="store_true",
        help=(
            "Generate a report for the "
            "latest simulation."
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# CLI dispatcher
# ---------------------------------------------------------------------------

def main(
    argv: Optional[list[str]] = None,
) -> int:
    """
    CLI entry point.

    Returns:
        Process exit code.
    """

    parser = build_parser()
    args = parser.parse_args(argv)

    # ---------------------------------------------------------------
    # Interactive mode
    # ---------------------------------------------------------------

    if not args.run_all and not args.report:
        return interactive_menu()

    context: ChainContext | None = None

    try:

        # -----------------------------------------------------------
        # Run simulation
        # -----------------------------------------------------------

        if args.run_all:
            context = run_all()

        # -----------------------------------------------------------
        # Generate report
        # -----------------------------------------------------------

        if args.report:

            if context is None:
                context = get_latest_context()

            if context is None:

                print(
                    "[!] No simulation available "
                    "for reporting.",
                    file=sys.stderr,
                )

                return 1

            generate_reports(context)

        # -----------------------------------------------------------
        # Exit status
        # -----------------------------------------------------------

        if context is not None:

            if context.metadata.status == ChainStatus.FAILED:
                return 1

            if context.metadata.status == ChainStatus.BLOCKED:
                return 2

        return 0

    except KeyboardInterrupt:

        print(
            "\n[!] Simulation interrupted."
        )

        return 130

    except Exception as exc:

        print(
            f"[!] CLI error: {exc}",
            file=sys.stderr,
        )

        return 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())