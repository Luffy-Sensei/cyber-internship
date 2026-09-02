from __future__ import annotations

import json
import logging
from pathlib import Path

from .firewall import FirewallAdapter
from .models import FirewallMode
from .policies import get_default_policy
from .validation import ValidationEngine


LOGGER = logging.getLogger(__name__)


def load_payload(path: str | Path) -> dict:
    """Load a JSON validation feed from disk."""
    feed_path = Path(path)

    with feed_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, dict):
        raise ValueError("validation feed root must be a JSON object")

    return payload


def configure_logging(log_path: str | Path) -> None:
    """Configure deterministic file logging for validation evidence."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
        ],
        force=True,
    )


def run_validation(
    feed_path: str | Path,
    *,
    log_path: str | Path | None = None,
) -> int:
    """Run the controlled validation pipeline.

    Only validated indicators are allowed to reach policy evaluation
    and the firewall adapter. Firewall execution remains DRY-RUN.
    """
    payload = load_payload(feed_path)

    if log_path is not None:
        configure_logging(log_path)

    feed_id = payload["feed_id"]
    source = payload["source"]
    indicators = payload["indicators"]

    validation = ValidationEngine().validate(
        feed_id=feed_id,
        source=source,
        indicators=indicators,
    )

    policy = get_default_policy()
    firewall = FirewallAdapter(mode=FirewallMode.DRY_RUN)

    decisions = tuple(
        policy.evaluate(indicator)
        for indicator in validation.valid_indicators
    )

    executions = firewall.process_many(
        decisions,
        source=source,
    )

    print()
    print("DAY 24 - ADVERSARIAL THREAT INTEL VALIDATION")
    print("=" * 72)
    print(f"Feed ID              : {validation.feed_id}")
    print(f"Feed Source          : {validation.source}")
    print(f"Indicators Received  : {validation.indicators_received}")
    print(f"Indicators Valid     : {validation.indicators_valid}")
    print(f"Indicators Rejected  : {validation.indicators_rejected}")
    print(f"Policy               : {policy.name}")
    print(f"Execution Mode       : {firewall.mode.value}")
    print()

    print("[VALID INTELLIGENCE]")
    print("-" * 72)

    for indicator, decision, execution in zip(
        validation.valid_indicators,
        decisions,
        executions,
    ):
        print(f"IP       : {indicator.ip}")
        print(f"Indicator: {indicator.indicator}")
        print(f"Risk     : {indicator.risk_score}")
        print(f"Decision : {decision.action.value}")
        print(f"Status   : {execution.status.value}")
        print(f"Firewall : {execution.mode.value}")
        print("-" * 72)

        LOGGER.info(
            "VALID indicator=%s ip=%s risk=%d decision=%s status=%s mode=%s",
            indicator.indicator,
            indicator.ip,
            indicator.risk_score,
            decision.action.value,
            execution.status.value,
            execution.mode.value,
        )

    print()
    print("[REJECTED INTELLIGENCE]")
    print("-" * 72)

    for rejected in validation.rejected_indicators:
        raw_ip = (
            rejected.raw_entry.get("ip", "<missing>")
            if isinstance(rejected.raw_entry, dict)
            else "<non-object>"
        )

        print(f"Index    : {rejected.index}")
        print(f"IP       : {raw_ip}")
        print(f"Reason   : {rejected.reason}")
        print("Action   : REJECTED")
        print("Firewall : NO ACTION")
        print("-" * 72)

        LOGGER.warning(
            "REJECTED indicator_index=%d ip=%s reason=%s firewall_action=NONE",
            rejected.index,
            raw_ip,
            rejected.reason,
        )

    rejected_ips = {
        rejected.raw_entry.get("ip")
        for rejected in validation.rejected_indicators
        if isinstance(rejected.raw_entry, dict)
    }

    decision_ips = {
        decision.ip
        for decision in decisions
    }

    execution_ips = {
        execution.ip
        for execution in executions
    }

    boundary_safe = (
        decision_ips.isdisjoint(rejected_ips)
        and execution_ips.isdisjoint(rejected_ips)
        and firewall.mode is FirewallMode.DRY_RUN
    )

    print()
    print("[SECURITY BOUNDARY]")
    print("=" * 72)
    print("Valid intelligence")
    print("       |")
    print("       v")
    print("Policy evaluation")
    print("       |")
    print("       v")
    print("Firewall DRY-RUN")
    print()
    print("Malformed intelligence")
    print("       |")
    print("       v")
    print("Rejected")
    print("       |")
    print("       v")
    print("NO FIREWALL ACTION")
    print()

    print(f"Rejected → Policy    : {'NONE' if decision_ips.isdisjoint(rejected_ips) else 'VIOLATION'}")
    print(f"Rejected → Firewall  : {'NONE' if execution_ips.isdisjoint(rejected_ips) else 'VIOLATION'}")
    print(f"Firewall Modification: {'NONE' if firewall.mode is FirewallMode.DRY_RUN else 'ENABLED'}")
    print(f"Boundary Validation  : {'PASS' if boundary_safe else 'FAIL'}")

    LOGGER.info(
        "BOUNDARY validation=%s rejected=%d decisions=%d executions=%d firewall_mode=%s",
        "PASS" if boundary_safe else "FAIL",
        validation.indicators_rejected,
        len(decisions),
        len(executions),
        firewall.mode.value,
    )

    return 0 if boundary_safe else 1


def main() -> int:
    """CLI entry point for controlled adversarial validation."""
    base_dir = Path(__file__).resolve().parent.parent

    return run_validation(
        base_dir / "input" / "validation-threat-feed.json",
        log_path=base_dir / "output" / "logs" / "day24_validation.log",
    )


if __name__ == "__main__":
    raise SystemExit(main())
