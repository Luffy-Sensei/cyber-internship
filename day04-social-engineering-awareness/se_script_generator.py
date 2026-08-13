#!/usr/bin/env python3

"""
Day 04 — Vishing & Smishing Awareness Scenario Generator
Sqrock Cybersecurity Internship - Phase 1

Generates structured social-engineering awareness scenarios for
security-awareness training.

Author: Fazal Hammad Khan
Date: 2026-08-13
Version: 2.2
"""

import json
import argparse
import random
import sys
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Path(__file__).resolve().parent / 'output' / 'awareness_generator.log'),

    ]
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VERSION = "2.2"

OUTPUT_DIR = Path(__file__).resolve().parent / "output"
OUTPUT_FILE = OUTPUT_DIR / "awareness_scenarios.json"
REPORT_FILE = OUTPUT_DIR / "awareness_report.txt"

# ---------------------------------------------------------------------------
# Awareness scenario templates
# ---------------------------------------------------------------------------

SCENARIO_TEMPLATES = {
    "vishing": {
        "channel": "Voice Call",
        "description": "Voice phishing - attacker impersonates authority figure over phone",
        "default_roles": [
            "IT Support Specialist",
            "Bank Security Officer",
            "Government Agent",
            "Technical Support Engineer",
            "HR Representative"
        ],
        "default_pretexts": [
            "Password Reset Required",
            "Suspicious Account Activity",
            "Security Breach Alert",
            "System Update Required",
            "Payment Verification"
        ],
        "triggers": ["authority", "fear", "liking"],
        "complexity": "beginner"
    },
    "smishing": {
        "channel": "SMS/Text Message",
        "description": "SMS phishing - attacker sends malicious links via text",
        "default_roles": [
            "Account Security Team",
            "Bank Fraud Department",
            "Package Delivery Service",
            "Mobile Carrier",
            "Payment Service"
        ],
        "default_pretexts": [
            "Account Verification Required",
            "Package Delivery Failed",
            "Suspicious Login Detected",
            "Payment Declined",
            "Prize Claim Required"
        ],
        "triggers": ["authority", "urgency", "scarcity"],
        "complexity": "beginner"
    }
}

# ---------------------------------------------------------------------------
# Psychological trigger analysis
# ---------------------------------------------------------------------------

TRIGGER_DESCRIPTIONS = {
    "authority": {
        "name": "Authority",
        "description": (
            "The scenario relies on an apparently trusted role or organization "
            "to increase perceived legitimacy."
        ),
        "example": "Caller claims to be from IT Security Department",
        "defense": "Always verify identity through independent channels"
    },
    "scarcity": {
        "name": "Scarcity",
        "description": (
            "The scenario presents a limited-time opportunity or consequence "
            "to create artificial value."
        ),
        "example": "Only 2 hours left to verify your account",
        "defense": "Legitimate organizations don't use artificial deadlines"
    },
    "fear": {
        "name": "Fear",
        "description": (
            "The scenario introduces a possible negative consequence to "
            "encourage immediate action."
        ),
        "example": "Your account will be permanently locked",
        "defense": "Stay calm and verify through official channels"
    },
    "liking": {
        "name": "Liking",
        "description": (
            "The scenario uses friendliness, rapport, or common interests "
            "to increase trust."
        ),
        "example": "Caller is friendly and 'helpful' to gain trust",
        "defense": "Remember: legitimate agents remain professional"
    },
    "urgency": {
        "name": "Urgency",
        "description": (
            "The scenario pressures the target to act quickly without thinking critically."
        ),
        "example": "Immediate action required within 15 minutes",
        "defense": "Take a moment to pause and evaluate the request independently"
    }
}


def analyze_psychological_triggers(triggers: List[str]) -> List[Dict]:
    """
    Convert trigger names into structured awareness-analysis records.
    """
    analysis = []

    for trigger in triggers:
        trigger_info = TRIGGER_DESCRIPTIONS.get(
            trigger,
            {
                "name": trigger.replace("_", " ").title(),
                "description": "Unclassified psychological trigger.",
                "example": "No example available",
                "defense": "Always verify independently"
            }
        )

        analysis.append({
            "trigger": trigger,
            "name": trigger_info["name"],
            "description": trigger_info["description"],
            "example": trigger_info["example"],
            "defense": trigger_info["defense"]
        })

    return analysis


# ---------------------------------------------------------------------------
# Red-flag identification
# ---------------------------------------------------------------------------

RED_FLAG_RULES = {
    "vishing": [
        {
            "indicator": "Credential Request",
            "severity": "critical",
            "reason": (
                "A caller requesting passwords, authentication codes, "
                "or other secrets is a major warning sign."
            )
        },
        {
            "indicator": "Unexpected Contact",
            "severity": "high",
            "reason": (
                "Unsolicited calls about account problems should be "
                "independently verified."
            )
        },
        {
            "indicator": "Authority Impersonation",
            "severity": "high",
            "reason": (
                "Claiming to represent IT, security, a bank, or another "
                "trusted authority can be used to create false trust."
            )
        },
        {
            "indicator": "Urgency or Pressure",
            "severity": "medium",
            "reason": (
                "Pressure to act immediately can prevent the recipient "
                "from independently verifying the request."
            )
        },
        {
            "indicator": "Threats of Consequences",
            "severity": "critical",
            "reason": (
                "Threatening account suspension, legal action, or other "
                "consequences is a common manipulation tactic."
            )
        }
    ],
    "smishing": [
        {
            "indicator": "Suspicious Link",
            "severity": "critical",
            "reason": (
                "Unexpected links in SMS messages should not be trusted "
                "without independent verification."
            )
        },
        {
            "indicator": "Unexpected Message",
            "severity": "high",
            "reason": (
                "An unsolicited security or account notification should "
                "be verified through an official channel."
            )
        },
        {
            "indicator": "Urgency or Pressure",
            "severity": "high",
            "reason": (
                "Threats of immediate account suspension can encourage "
                "impulsive clicking."
            )
        },
        {
            "indicator": "Sender Impersonation",
            "severity": "high",
            "reason": (
                "A message may claim to represent a trusted organization "
                "without actually originating from it."
            )
        },
        {
            "indicator": "Too Good to Be True",
            "severity": "medium",
            "reason": (
                "Promises of prizes, refunds, or rewards are often "
                "used to entice victims to click malicious links."
            )
        }
    ]
}


def identify_red_flags(scenario_type: str) -> List[Dict]:
    """
    Return the awareness indicators associated with a scenario type.
    """
    if scenario_type not in RED_FLAG_RULES:
        raise ValueError(f"Unsupported scenario type: {scenario_type}")

    return RED_FLAG_RULES[scenario_type]


# ---------------------------------------------------------------------------
# Defensive guidance
# ---------------------------------------------------------------------------

DEFENSIVE_GUIDANCE = {
    "vishing": [
        {
            "action": "Never disclose secrets",
            "detail": (
                "Never share passwords, authentication codes, or "
                "security questions over the phone."
            )
        },
        {
            "action": "Verify independently",
            "detail": (
                "End the call and contact the organization using "
                "official phone numbers from their website."
            )
        },
        {
            "action": "Don't trust caller ID",
            "detail": (
                "Caller ID can be spoofed to display any number "
                "the attacker chooses."
            )
        },
        {
            "action": "Take your time",
            "detail": (
                "Legitimate organizations will not pressure you "
                "to make immediate decisions."
            )
        },
        {
            "action": "Report suspicious calls",
            "detail": (
                "Report suspicious social-engineering attempts "
                "to your security team or IT department."
            )
        }
    ],
    "smishing": [
        {
            "action": "Don't click links",
            "detail": (
                "Never click links in unexpected SMS messages, "
                "even if they appear legitimate."
            )
        },
        {
            "action": "Verify through official apps",
            "detail": (
                "Check account status through the organization's "
                "official website or mobile application."
            )
        },
        {
            "action": "Don't reply to suspicious texts",
            "detail": (
                "Replying confirms your number is active and may "
                "lead to more attacks."
            )
        },
        {
            "action": "Block and report",
            "detail": (
                "Block the sender and report the message to your "
                "mobile carrier and security team."
            )
        },
        {
            "action": "Forward to spam services",
            "detail": (
                "Forward suspicious texts to 7726 (SPAM) in the US "
                "or your country's equivalent."
            )
        }
    ]
}


def generate_defensive_guidance(scenario_type: str) -> List[Dict]:
    """
    Return defensive recommendations for the scenario type.
    """
    if scenario_type not in DEFENSIVE_GUIDANCE:
        raise ValueError(f"Unsupported scenario type: {scenario_type}")

    return DEFENSIVE_GUIDANCE[scenario_type]


# ---------------------------------------------------------------------------
# Script generation
# ---------------------------------------------------------------------------

def generate_vishing_script(target_company: str, attacker_role: str, pretext: str) -> Dict:
    """
    Generate a vishing awareness scenario with multiple phases.
    """
    return {
        "phase_1_opener": (
            f"Caller claims to be {attacker_role} from {target_company}. "
            "Uses professional tone to establish credibility."
        ),
        "phase_2_pretext": (
            f"The caller explains: '{pretext}' and states this requires "
            "immediate attention."
        ),
        "phase_3_hook": (
            "The scenario introduces an account or security concern "
            "designed to create urgency and fear."
        ),
        "phase_4_request": (
            "The simulated caller attempts to obtain sensitive "
            "information such as passwords, OTPs, or account details."
        ),
        "phase_5_pressure": (
            "If met with resistance, the caller increases urgency by "
            "threatening account suspension or security breaches."
        ),
        "awareness_note": (
            "This script demonstrates how vishing attacks use authority "
            "and fear to manipulate victims into sharing sensitive data."
        )
    }


def generate_smishing_script(target_company: str, pretext: str) -> Dict:
    """
    Generate a smishing awareness scenario.
    """
    example_url = generate_demo_url(pretext, target_company)

    return {
        "message_content": (
            f"[{target_company}] ALERT: {pretext}. "
            f"Verify your account immediately: {example_url}"
        ),
        "pretext": (
            f"The message claims that action is required because of: "
            f"{pretext}."
        ),
        "hook": (
            "The message uses urgency and fear to encourage the recipient "
            "to click the link without verification."
        ),
        "request": (
            "The link leads to a fake login page designed to steal "
            "credentials or install malware."
        ),
        "awareness_note": (
            "This demonstrates how smishing uses shortened URLs and "
            "urgency to trick victims into clicking malicious links."
        )
    }


def generate_demo_url(pretext: str, target_company: Optional[str] = None) -> str:
    """
    Generate a realistic-looking but clearly fake URL for demonstration.
    """
    domains = [
        "verify-account-now.com",
        "security-alert-portal.net",
        "account-verification-required.org",
        "urgent-security-check.com",
        "secure-login-verify.net"
    ]

    domain = random.choice(domains)

    # Create unique path using timestamp to avoid collisions
    timestamp = datetime.now(timezone.utc).strftime("%H%M%S%f")
    path = pretext.lower().replace(" ", "-")

    if target_company:
        company_slug = target_company.lower().replace(" ", "-")
        path = f"{company_slug}-{path}"

    # Add random suffix for uniqueness
    random_suffix = ''.join(random.choices('abcdef0123456789', k=6))

    return f"https://{domain}/{path}-{random_suffix}"


# ---------------------------------------------------------------------------
# Complete scenario builder
# ---------------------------------------------------------------------------

def generate_scenario(
    scenario_type: str,
    target_company: str,
    role: str,
    pretext: str,
    triggers: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Build a complete structured awareness scenario.
    """
    if scenario_type not in SCENARIO_TEMPLATES:
        raise ValueError(f"Unsupported scenario type: {scenario_type}")

    if not target_company or not target_company.strip():
        raise ValueError("Target company cannot be empty")

    if triggers is None:
        triggers = SCENARIO_TEMPLATES[scenario_type]["triggers"]

    valid_triggers = set(TRIGGER_DESCRIPTIONS.keys())
    invalid_triggers = set(triggers) - valid_triggers
    if invalid_triggers:
        raise ValueError(f"Invalid triggers: {invalid_triggers}")

    if scenario_type == "vishing":
        script = generate_vishing_script(target_company, role, pretext)
    else:
        script = generate_smishing_script(target_company, pretext)

    return {
        "scenario_id": generate_scenario_id(),
        "scenario_type": scenario_type,
        "channel": SCENARIO_TEMPLATES[scenario_type]["channel"],
        "description": SCENARIO_TEMPLATES[scenario_type]["description"],
        "complexity": SCENARIO_TEMPLATES[scenario_type]["complexity"],
        "target_company": target_company,
        "impersonated_role": role,
        "pretext": pretext,
        "psychological_triggers": analyze_psychological_triggers(triggers),
        "script": script,
        "red_flags": identify_red_flags(scenario_type),
        "defensive_guidance": generate_defensive_guidance(scenario_type)
    }


def generate_scenario_id() -> str:
    """
    Generate a unique ID for each scenario.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    random_suffix = ''.join(random.choices('0123456789ABCDEF', k=4))
    return f"SE-{timestamp}-{random_suffix}"


# ---------------------------------------------------------------------------
# Interactive quiz generation
# ---------------------------------------------------------------------------

def generate_quiz_questions(scenario: Dict) -> List[Dict]:
    """
    Generate awareness quiz questions based on the scenario.
    """
    questions = []

    # Question 1: Identify the attack type
    questions.append({
        "question": "What type of social engineering attack is this?",
        "options": [
            "Vishing (Voice Phishing)",
            "Smishing (SMS Phishing)",
            "Phishing (Email)",
            "Physical intrusion"
        ],
        "correct_answer": 0 if scenario["scenario_type"] == "vishing" else 1,
        "explanation": (
            f"This is a {scenario['scenario_type']} attack because it uses "
            f"{scenario['channel'].lower()} as the attack vector."
        )
    })

    # Question 2: Identify the primary trigger
    triggers = scenario.get("psychological_triggers", [])

    if triggers:
        primary_trigger_name = triggers[0]["name"]
        all_options = [info["name"] for info in TRIGGER_DESCRIPTIONS.values()]

        if primary_trigger_name in all_options:
            correct_idx = all_options.index(primary_trigger_name)
        else:
            all_options.append(primary_trigger_name)
            correct_idx = len(all_options) - 1

        explanation = triggers[0]["description"]
    else:
        # Fallback if no triggers available
        primary_trigger_name = "Authority"
        all_options = [info["name"] for info in TRIGGER_DESCRIPTIONS.values()]
        correct_idx = 0 if "Authority" in all_options else 0
        explanation = "No psychological trigger analysis available."

    questions.append({
        "question": "What is the primary psychological trigger being used?",
        "options": all_options,
        "correct_answer": correct_idx,
        "explanation": explanation
    })

    # Question 3: Best response
    questions.append({
        "question": "What is the BEST response to this scenario?",
        "options": [
            "Provide the requested information",
            "Click the link to verify",
            "Independently verify through official channels",
            "Ignore it completely"
        ],
        "correct_answer": 2,
        "explanation": (
            "Always verify independently using official contact "
            "information, not information provided by the attacker."
        )
    })

    return questions


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def build_report(
    scenario_types: Optional[List[str]] = None,
    target_company: str = "Sqrock IT"
) -> Dict:
    """
    Generate the complete Day 04 awareness dataset.
    """
    scenarios = []

    if scenario_types is None:
        scenario_types = list(SCENARIO_TEMPLATES.keys())
    elif not scenario_types:
        raise ValueError("scenario_types cannot be an empty list")

    if not target_company or not target_company.strip():
        raise ValueError("Target company cannot be empty")

    for scenario_type in scenario_types:
        if scenario_type not in SCENARIO_TEMPLATES:
            logger.warning(f"Skipping unsupported scenario type: {scenario_type}")
            continue

        template = SCENARIO_TEMPLATES[scenario_type]

        role = random.choice(template["default_roles"])
        pretext = random.choice(template["default_pretexts"])

        scenario = generate_scenario(
            scenario_type=scenario_type,
            target_company=target_company,
            role=role,
            pretext=pretext,
            triggers=template["triggers"]
        )

        scenario["quiz"] = generate_quiz_questions(scenario)
        scenarios.append(scenario)

    return {
        "scan_metadata": {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "generator": f"Day 04 Social Engineering Awareness Engine v{VERSION}",
            "scenarios_generated": len(scenarios),
            "target_organization": target_company
        },
        "results": scenarios,
        "statistics": generate_statistics(scenarios)
    }


def generate_statistics(scenarios: List[Dict]) -> Dict:
    """
    Generate statistics about the scenarios.
    """
    stats = {
        "total_scenarios": len(scenarios),
        "channels": {},
        "triggers_used": {},
        "red_flags_total": 0,
        "defensive_guidance_total": 0
    }

    for scenario in scenarios:
        channel = scenario["channel"]
        stats["channels"][channel] = stats["channels"].get(channel, 0) + 1

        for trigger in scenario["psychological_triggers"]:
            trigger_name = trigger["name"]
            stats["triggers_used"][trigger_name] = (
                stats["triggers_used"].get(trigger_name, 0) + 1
            )

        stats["red_flags_total"] += len(scenario["red_flags"])
        stats["defensive_guidance_total"] += len(scenario["defensive_guidance"])

    # Sort triggers for deterministic output
    stats["triggers_used"] = dict(sorted(stats["triggers_used"].items()))
    stats["channels"] = dict(sorted(stats["channels"].items()))

    return stats


# ---------------------------------------------------------------------------
# File output
# ---------------------------------------------------------------------------

def save_report(report: Dict) -> None:
    """
    Save structured JSON output and text report.
    """
    try:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        with OUTPUT_FILE.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=4, ensure_ascii=False)
        logger.info(f"JSON report saved to: {OUTPUT_FILE}")

        with REPORT_FILE.open("w", encoding="utf-8") as file:
            file.write(generate_text_report(report))
        logger.info(f"Text report saved to: {REPORT_FILE}")

    except PermissionError as e:
        logger.error(f"Permission denied writing to output directory: {e}")
        raise
    except OSError as e:
        logger.error(f"OS error writing files: {e}")
        raise
    except json.JSONEncodeError as e:
        logger.error(f"JSON encoding error: {e}")
        raise


def generate_text_report(report: Dict) -> str:
    """
    Generate a human-readable text report.
    """
    lines = []
    lines.append("=" * 70)
    lines.append("SOCIAL ENGINEERING AWARENESS REPORT")
    lines.append("Day 04: Vishing & Smishing Scenarios")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Generated: {report['scan_metadata']['timestamp_utc']}")
    lines.append(f"Organization: {report['scan_metadata']['target_organization']}")
    lines.append(f"Total Scenarios: {report['scan_metadata']['scenarios_generated']}")
    lines.append("")

    for idx, scenario in enumerate(report["results"], 1):
        lines.append("-" * 70)
        lines.append(f"SCENARIO {idx}: {scenario['scenario_type'].upper()}")
        lines.append("-" * 70)
        lines.append(f"Channel: {scenario['channel']}")
        lines.append(f"Target: {scenario['target_company']}")
        lines.append(f"Impersonated Role: {scenario['impersonated_role']}")
        lines.append(f"Pretext: {scenario['pretext']}")
        lines.append("")

        lines.append("PSYCHOLOGICAL TRIGGERS:")
        for trigger in scenario["psychological_triggers"]:
            lines.append(f"  • {trigger['name']}: {trigger['description']}")
        lines.append("")

        lines.append("SCRIPT:")
        for key, value in scenario["script"].items():
            lines.append(f"  [{key.replace('_', ' ').upper()}]")
            lines.append(f"  {value}")
        lines.append("")

        lines.append("RED FLAGS:")
        for flag in scenario["red_flags"]:
            lines.append(f"  • {flag['indicator']} ({flag['severity']}): {flag['reason']}")
        lines.append("")

        lines.append("DEFENSIVE GUIDANCE:")
        for guidance in scenario["defensive_guidance"]:
            lines.append(f"  • {guidance['action']}: {guidance['detail']}")
        lines.append("")

        lines.append("QUIZ QUESTIONS:")
        for q_idx, question in enumerate(scenario.get("quiz", []), 1):
            lines.append(f"  Q{q_idx}: {question['question']}")
            lines.append(f"  Correct Answer: {question['options'][question['correct_answer']]}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Console presentation
# ---------------------------------------------------------------------------

def print_summary(report: Dict) -> None:
    """
    Display a concise human-readable summary with colors.
    """
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.YELLOW}🔒 DAY 04: VISHING & SMISHING AWARENESS ENGINE")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}[+] {Style.BRIGHT}Scenario Generation Complete")
    print(f"{Fore.WHITE}├── Generated: {report['scan_metadata']['timestamp_utc']}")
    print(f"├── Organization: {report['scan_metadata']['target_organization']}")
    print(f"└── Total Scenarios: {report['scan_metadata']['scenarios_generated']}")

    stats = report["statistics"]
    print(f"\n{Fore.CYAN}📊 STATISTICS{Style.RESET_ALL}")
    print(f"{Fore.WHITE}├── Channels Used:")
    for channel, count in stats["channels"].items():
        print(f"│   └── {channel}: {count}")
    print(f"├── Total Red Flags: {stats['red_flags_total']}")
    print(f"└── Total Defensive Guidance: {stats['defensive_guidance_total']}")

    print(f"\n{Fore.MAGENTA}📋 SCENARIO DETAILS{Style.RESET_ALL}")

    for index, scenario in enumerate(report["results"], start=1):
        print(f"\n{Fore.YELLOW}🔍 Scenario {index}: {scenario['scenario_type'].upper()}")
        print(f"{Fore.WHITE}├── Channel: {scenario['channel']}")
        print(f"├── Target: {scenario['target_company']}")
        print(f"├── Role: {scenario['impersonated_role']}")
        print(f"├── Pretext: {scenario['pretext']}")
        print(f"├── Triggers: ", end="")

        trigger_names = [t["name"] for t in scenario["psychological_triggers"]]
        print(f"{', '.join(trigger_names)}")

        print(f"├── Red Flags: {len(scenario['red_flags'])}")
        print(f"├── Defensive Guidance: {len(scenario['defensive_guidance'])}")
        print(f"└── Quiz Questions: {len(scenario.get('quiz', []))}")

    print(f"\n{Fore.GREEN}✅ Full report saved to: {OUTPUT_FILE}")
    print(f"✅ Text report saved to: {REPORT_FILE}{Style.RESET_ALL}\n")


def print_detailed_scenario(scenario: Dict) -> None:
    """
    Print detailed scenario information for review.
    """
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.YELLOW}SCENARIO: {scenario['scenario_type'].upper()}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")

    print(f"\n{Fore.WHITE}📌 OVERVIEW")
    print(f"├── Channel: {scenario['channel']}")
    print(f"├── Target: {scenario['target_company']}")
    print(f"├── Role: {scenario['impersonated_role']}")
    print(f"└── Pretext: {scenario['pretext']}")

    print(f"\n{Fore.YELLOW}🎯 PSYCHOLOGICAL TRIGGERS{Style.RESET_ALL}")
    for trigger in scenario["psychological_triggers"]:
        print(f"{Fore.WHITE}├── {trigger['name']}")
        print(f"│   ├── Description: {trigger['description']}")
        print(f"│   ├── Example: {trigger['example']}")
        print(f"│   └── Defense: {trigger['defense']}")

    print(f"\n{Fore.RED}🚩 RED FLAGS{Style.RESET_ALL}")
    for flag in scenario["red_flags"]:
        print(f"{Fore.WHITE}├── {flag['indicator']} [{flag['severity'].upper()}]")
        print(f"│   └── {flag['reason']}")

    print(f"\n{Fore.GREEN}🛡️ DEFENSIVE GUIDANCE{Style.RESET_ALL}")
    for guidance in scenario["defensive_guidance"]:
        print(f"{Fore.WHITE}├── {guidance['action']}")
        print(f"│   └── {guidance['detail']}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Main entry point with CLI argument parsing.
    """
    global OUTPUT_DIR, OUTPUT_FILE, REPORT_FILE
    parser = argparse.ArgumentParser(
        description="Day 04: Vishing & Smishing Awareness Scenario Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python day04_scenario_generator.py
  python day04_scenario_generator.py --type vishing
  python day04_scenario_generator.py --type both --company "Sqrock IT"
  python day04_scenario_generator.py --interactive
        """
    )

    parser.add_argument(
        "--type",
        choices=["vishing", "smishing", "both"],
        default="both",
        help="Type of scenarios to generate (default: both)"
    )

    parser.add_argument(
        "--company",
        default="Sqrock IT",
        help="Target company name (default: Sqrock IT)"
    )

    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Enable interactive mode with detailed output"
    )

    parser.add_argument(
        "--output-dir",
        default=None,
        help="Custom output directory"
    )

    args = parser.parse_args()

  # Update globals if custom output directory provided
    if args.output_dir:
        OUTPUT_DIR = Path(args.output_dir)
        OUTPUT_FILE = OUTPUT_DIR / "awareness_scenarios.json"
        REPORT_FILE = OUTPUT_DIR / "awareness_report.txt"

    if args.type == "both":
        scenario_types = ["vishing", "smishing"]
    else:
        scenario_types = [args.type]

    try:
        # Validate company name
        if not args.company or not args.company.strip():
            raise ValueError("Company name cannot be empty")

        report = build_report(
            scenario_types=scenario_types,
            target_company=args.company.strip()
        )

        save_report(report)
        print_summary(report)
        save_report(report)
        print_summary(report)

        if args.interactive:
            print(f"\n{Fore.CYAN}🎮 INTERACTIVE MODE{Style.RESET_ALL}")
            for scenario in report["results"]:
                print_detailed_scenario(scenario)

                print(f"\n{Fore.YELLOW}📝 AWARENESS QUIZ{Style.RESET_ALL}")
                for q_idx, question in enumerate(scenario["quiz"], 1):
                    print(f"\n{Fore.WHITE}Question {q_idx}: {question['question']}")
                    for opt_idx, option in enumerate(question["options"], 1):
                        print(f"  {opt_idx}. {option}")

                    while True:
                        try:
                            answer = input(f"{Fore.CYAN}Your answer (1-{len(question['options'])}): {Style.RESET_ALL}")
                            answer = int(answer)
                            if 1 <= answer <= len(question["options"]):
                                break
                            print(f"{Fore.RED}Please enter a number between 1 and {len(question['options'])}{Style.RESET_ALL}")
                        except ValueError:
                            print(f"{Fore.RED}Please enter a valid number{Style.RESET_ALL}")
                        except KeyboardInterrupt:
                            print(f"\n{Fore.YELLOW}Exiting quiz...{Style.RESET_ALL}")
                            return

                    if answer - 1 == question["correct_answer"]:
                        print(f"{Fore.GREEN}✅ Correct!{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}❌ Incorrect. Correct answer: {question['options'][question['correct_answer']]}{Style.RESET_ALL}")

                    print(f"{Fore.WHITE}Explanation: {question['explanation']}{Style.RESET_ALL}")

                input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user{Style.RESET_ALL}")
        sys.exit(0)
    except ValueError as e:
        print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
        logger.error(f"Validation error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
        logger.exception("Unexpected error occurred")
        sys.exit(1)


if __name__ == "__main__":
    main()
