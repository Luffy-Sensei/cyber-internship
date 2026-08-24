#!/usr/bin/env python3

"""
SE Chain Simulator - Configuration

Centralized application configuration for the SE Chain Simulator.
"""

from pathlib import Path
import json
from typing import Any


# ---------------------------------------------------------------------------
# Project Paths
# ---------------------------------------------------------------------------

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent

INPUT_DIR = PROJECT_ROOT / "input"
OUTPUT_DIR = PROJECT_ROOT / "output"

RUNS_DIR = OUTPUT_DIR / "runs"
REPORTS_DIR = OUTPUT_DIR / "reports"

LAB_TARGET_FILE = INPUT_DIR / "lab_target.json"


# ---------------------------------------------------------------------------
# Application Metadata
# ---------------------------------------------------------------------------

APP_NAME = "SE Chain Simulator"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = (
    "Authorized social engineering attack-chain simulation framework"
)


# ---------------------------------------------------------------------------
# Execution Modes
# ---------------------------------------------------------------------------

MODE_LAB = "lab"
MODE_DRY_RUN = "dry-run"

SUPPORTED_MODES = {
    MODE_LAB,
    MODE_DRY_RUN,
}


# ---------------------------------------------------------------------------
# Chain Stages
# ---------------------------------------------------------------------------

CHAIN_STAGES = (
    "osint",
    "profile",
    "phish",
    "template",
    "delivery",
    "exploit",
    "persist",
    "ir",
)


# ---------------------------------------------------------------------------
# Configuration Loader
# ---------------------------------------------------------------------------

def load_lab_target() -> dict[str, Any]:
    """
    Load the authorized laboratory target configuration.

    Returns:
        Dictionary containing lab target configuration.

    Raises:
        FileNotFoundError:
            If the lab configuration file does not exist.

        ValueError:
            If the configuration is invalid JSON.
    """

    if not LAB_TARGET_FILE.exists():
        raise FileNotFoundError(
            f"Lab target configuration not found: {LAB_TARGET_FILE}"
        )

    try:
        with LAB_TARGET_FILE.open("r", encoding="utf-8") as file:
            return json.load(file)

    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in lab target configuration: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Output Directory Initialization
# ---------------------------------------------------------------------------

def initialize_directories() -> None:
    """
    Ensure required output directories exist.
    """

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
