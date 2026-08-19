#!/usr/bin/env python3

"""
Day 08 — USB Drop Attack Simulation

Benign USB payload simulation for security-awareness training.

The simulator collects non-sensitive local system metadata and
writes it to a local evidence file. It does not implement
autorun, persistence, credential theft, exfiltration, or
malicious execution.
"""

import argparse
import datetime
import os
import platform
import socket
from pathlib import Path


DEFAULT_OUTPUT = Path("output/recon_log.txt")


def collect_system_info():
    """Collect basic local system metadata."""

    return {
        "timestamp": datetime.datetime.now().astimezone().isoformat(),
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "version": platform.version(),
        "user": os.getenv("USERNAME") or os.getenv("USER") or "unknown",
        "cwd": os.getcwd(),
    }


def write_report(info, output_file):
    """Write collected metadata to the evidence file."""

    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as file:
        for key, value in info.items():
            file.write(f"{key}: {value}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Day 08 benign USB payload simulator."
    )

    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Output file for simulated reconnaissance data.",
    )

    args = parser.parse_args()

    print("=" * 70)
    print("🔌 DAY 08 — USB DROP ATTACK SIMULATION")
    print("=" * 70)
    print()
    print("[SIM] Executing benign local payload simulation...")
    print("[SIM] No autorun, persistence, credential access, or exfiltration.")
    print()

    info = collect_system_info()
    output_file = Path(args.output)

    write_report(info, output_file)

    print("[+] Simulation complete")
    print(f"[+] Hostname : {info['hostname']}")
    print(f"[+] OS       : {info['os']}")
    print(f"[+] User     : {info['user']}")
    print(f"[+] Output   : {output_file.resolve()}")
    print()
    print("✅ Benign USB payload simulation complete.")


if __name__ == "__main__":
    main()
