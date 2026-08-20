#!/usr/bin/env python3

"""
Day 09 — Social Media Impersonation & Fake Profile Detection

A local, rule-based fake-profile and bot-risk detector.

The program analyzes supplied profile metadata and assigns a
risk score based on behavioral heuristics.

This tool does NOT access social-media platforms, scrape accounts,
or determine with certainty whether an account is fake.

The score represents observed risk indicators only.
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"

DEFAULT_OUTPUT = OUTPUT_DIR / "fake_profile_results.json"
DEFAULT_PLATFORM = "twitter"

MAX_SCORE = 100

# Maximum contribution of each heuristic.
WEIGHTS = {
    "account_age": 30,
    "following_ratio": 25,
    "profile_picture": 20,
    "low_posts": 15,
    "default_bio": 10,
    "default_name": 10,
    "low_engagement": 15,
    "high_follower_growth": 20,
    "inconsistent_posting": 12,
    "language_inconsistency": 10,
    "high_hashtag_ratio": 10,
    "high_mention_ratio": 8,
    "high_reply_ratio": 12,
    "no_original_content": 15,
    "copy_paste_pattern": 20,
    "impersonation_signal": 20,
}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Demo profiles
# ---------------------------------------------------------------------------

DEMO_PROFILES = [
    {
        "username": "realsara",
        "name": "Sara Johnson",
        "bio": "Digital Marketing Manager | Coffee lover | Travel enthusiast",
        "account_age_days": 1200,
        "followers": 4500,
        "following": 320,
        "posts": 870,
        "no_profile_pic": False,
        "default_bio": False,
        "default_name": False,
        "engagement_rate": 3.5,
        "follower_growth_rate": 2.1,
        "post_consistency": True,
        "language_consistency": True,
        "hashtag_ratio": 0.15,
        "mention_ratio": 0.10,
        "reply_ratio": 0.20,
        "no_original_content": False,
        "copy_paste_pattern": False,
        "impersonation_signal": False,
    },
    {
        "username": "botty_mcbotface",
        "name": "Bot User",
        "bio": "Follow me for more!",
        "account_age_days": 5,
        "followers": 2,
        "following": 900,
        "posts": 1,
        "no_profile_pic": True,
        "default_bio": True,
        "default_name": True,
        "engagement_rate": 0,
        "follower_growth_rate": 0,
        "post_consistency": False,
        "language_consistency": False,
        "hashtag_ratio": 0.90,
        "mention_ratio": 0.80,
        "reply_ratio": 0.90,
        "no_original_content": True,
        "copy_paste_pattern": True,
        "impersonation_signal": False,
    },
    {
        "username": "crypto_lover",
        "name": "Crypto King",
        "bio": "Best crypto trading signals! DM me for details",
        "account_age_days": 15,
        "followers": 150,
        "following": 1200,
        "posts": 45,
        "no_profile_pic": True,
        "default_bio": False,
        "default_name": False,
        "engagement_rate": 8.5,
        "follower_growth_rate": 85.0,
        "post_consistency": False,
        "language_consistency": True,
        "hashtag_ratio": 0.70,
        "mention_ratio": 0.30,
        "reply_ratio": 0.60,
        "no_original_content": False,
        "copy_paste_pattern": False,
        "impersonation_signal": False,
    },
    {
        "username": "sara_johnson_official",
        "name": "Sara Johnson",
        "bio": "Official account",
        "account_age_days": 20,
        "followers": 18,
        "following": 600,
        "posts": 4,
        "no_profile_pic": True,
        "default_bio": True,
        "default_name": False,
        "engagement_rate": 0.2,
        "follower_growth_rate": 65.0,
        "post_consistency": False,
        "language_consistency": True,
        "hashtag_ratio": 0.20,
        "mention_ratio": 0.40,
        "reply_ratio": 0.30,
        "no_original_content": True,
        "copy_paste_pattern": False,
        "impersonation_signal": True,
    },
]


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def clamp_score(score: int) -> int:
    """Keep a score within the 0-100 range."""
    return max(0, min(score, MAX_SCORE))


def risk_level(score: int) -> str:
    """Convert numerical score into a risk category."""

    if score >= 70:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


def load_profiles(path: Path) -> List[Dict[str, Any]]:
    """Load profiles from a JSON file."""

    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)

    except FileNotFoundError:
        raise ValueError(f"Profile file not found: {path}")

    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON file: {exc}")

    if isinstance(data, dict):
        return [data]

    if isinstance(data, list):
        return data

    raise ValueError("JSON input must contain an object or list of objects.")


# ---------------------------------------------------------------------------
# Fake profile analyzer
# ---------------------------------------------------------------------------

class FakeProfileAnalyzer:
    """Rule-based fake profile and bot-risk analyzer."""

    def __init__(self, platform: str = DEFAULT_PLATFORM):
        self.platform = platform.lower()

    # -----------------------------------------------------------------------
    # Individual heuristic checks
    # -----------------------------------------------------------------------

    def check_account_age(
        self,
        profile: Dict[str, Any],
    ) -> tuple[int, str | None]:
        """Check whether the account is unusually new."""

        age = profile.get("account_age_days", 365)

        if age < 7:
            return WEIGHTS["account_age"], "Account is less than 7 days old."

        if age < 30:
            return 20, "Account is less than 30 days old."

        if age < 90:
            return 10, "Account is less than 90 days old."

        return 0, None

    def check_following_ratio(
        self,
        profile: Dict[str, Any],
    ) -> tuple[int, str | None]:
        """
        Check following-to-follower ratio.

        A high ratio can be a signal of follow-for-follow,
        spam, or automated behavior.
        """

        followers = max(int(profile.get("followers", 0)), 0)
        following = max(int(profile.get("following", 0)), 0)

        ratio = following / max(followers, 1)

        if ratio > 100:
            return 25, f"Extreme following/follower ratio: {ratio:.1f}:1."

        if ratio > 20:
            return 20, f"Very high following/follower ratio: {ratio:.1f}:1."

        if ratio > 10:
            return 15, f"High following/follower ratio: {ratio:.1f}:1."

        if ratio > 5:
            return 5, f"Elevated following/follower ratio: {ratio:.1f}:1."

        return 0, None

    def check_profile_picture(
        self,
        profile: Dict[str, Any],
    ) -> tuple[int, str | None]:
        """Check profile-picture indicators."""

        if profile.get("no_profile_pic", False):
            return 20, "No profile picture is configured."

        if profile.get("default_pic", False):
            return 10, "Default profile picture is being used."

        return 0, None

    def check_post_activity(
        self,
        profile: Dict[str, Any],
    ) -> tuple[int, str | None]:
        """Check for unusually low activity."""

        posts = max(int(profile.get("posts", 0)), 0)

        if posts < 3:
            return 15, f"Very low post count: {posts}."

        if posts < 10:
            return 8, f"Low post count: {posts}."

        return 0, None

    def check_bio(
        self,
        profile: Dict[str, Any],
    ) -> tuple[int, str | None]:
        """Check for missing or default bios."""

        if profile.get("default_bio", False):
            return 10, "Default or generic bio indicator detected."

        bio = str(profile.get("bio", "")).strip()

        if not bio:
            return 10, "Profile has no biography."

        generic_phrases = [
            "follow me",
            "follow back",
            "good vibes",
            "just a normal person",
            "simple person",
        ]

        bio_lower = bio.lower()

        if any(phrase in bio_lower for phrase in generic_phrases):
            return 5, "Generic social-media bio language detected."

        return 0, None

    def check_name(
        self,
        profile: Dict[str, Any],
    ) -> tuple[int, str | None]:
        """Check for generic/default naming patterns."""

        if profile.get("default_name", False):
            return 10, "Default or generic display name detected."

        name = str(profile.get("name", "")).strip().lower()

        if not name:
            return 5, "No display name provided."

        generic_names = {
            "user",
            "guest",
            "anonymous",
            "unknown",
            "visitor",
        }

        if name in generic_names:
            return 5, f"Generic display name detected: {name}."

        if re.fullmatch(r"[a-z0-9]{8,}", name):
            return 5, "Display name resembles a generated identifier."

        return 0, None

    def check_engagement(
        self,
        profile: Dict[str, Any],
    ) -> tuple[int, str | None]:
        """Check for unusually low engagement."""

        engagement = float(profile.get("engagement_rate", 0))

        if engagement < 0.5:
            return 15, f"Very low engagement rate: {engagement}%."

        if engagement < 1.5:
            return 8, f"Low engagement rate: {engagement}%."

        return 0, None

    def check_growth(
        self,
        profile: Dict[str, Any],
    ) -> tuple[int, str | None]:
        """Check for unusually rapid follower growth."""

        growth = float(profile.get("follower_growth_rate", 0))

        if growth > 100:
            return 20, f"Extremely high follower growth: {growth}% per day."

        if growth > 50:
            return 10, f"High follower growth: {growth}% per day."

        return 0, None

    def check_behavioral_patterns(
        self,
        profile: Dict[str, Any],
    ) -> List[tuple[str, int, str]]:
        """Check content and behavioral indicators."""

        findings = []

        if not profile.get("post_consistency", True):
            findings.append(
                (
                    "inconsistent_posting",
                    12,
                    "Inconsistent posting pattern detected.",
                )
            )

        if not profile.get("language_consistency", True):
            findings.append(
                (
                    "language_inconsistency",
                    10,
                    "Inconsistent language usage detected.",
                )
            )

        hashtag_ratio = float(profile.get("hashtag_ratio", 0))

        if hashtag_ratio > 0.5:
            findings.append(
                (
                    "high_hashtag_ratio",
                    10,
                    f"High hashtag ratio detected: {hashtag_ratio:.0%}.",
                )
            )

        mention_ratio = float(profile.get("mention_ratio", 0))

        if mention_ratio > 0.7:
            findings.append(
                (
                    "high_mention_ratio",
                    8,
                    f"High mention ratio detected: {mention_ratio:.0%}.",
                )
            )

        reply_ratio = float(profile.get("reply_ratio", 0))

        if reply_ratio > 0.8:
            findings.append(
                (
                    "high_reply_ratio",
                    12,
                    f"Very high reply ratio detected: {reply_ratio:.0%}.",
                )
            )

        if profile.get("no_original_content", False):
            findings.append(
                (
                    "no_original_content",
                    15,
                    "Profile contains no original-content indicator.",
                )
            )

        if profile.get("copy_paste_pattern", False):
            findings.append(
                (
                    "copy_paste_pattern",
                    20,
                    "Repeated copy-paste behavior detected.",
                )
            )

        if profile.get("impersonation_signal", False):
            findings.append(
                (
                    "impersonation_signal",
                    20,
                    "Potential impersonation indicator detected.",
                )
            )

        return findings

    # -----------------------------------------------------------------------
    # Complete analysis
    # -----------------------------------------------------------------------

    def analyze(self, profile: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze one profile and return a structured result."""

        username = profile.get("username", "unknown")

        score = 0
        findings = []
        breakdown = {}

        checks = [
            ("account_age", self.check_account_age),
            ("following_ratio", self.check_following_ratio),
            ("profile_picture", self.check_profile_picture),
            ("low_posts", self.check_post_activity),
            ("default_bio", self.check_bio),
            ("default_name", self.check_name),
            ("low_engagement", self.check_engagement),
            ("high_follower_growth", self.check_growth),
        ]

        for name, check in checks:
            points, message = check(profile)

            breakdown[name] = points
            score += points

            if message:
                findings.append(
                    {
                        "type": name,
                        "points": points,
                        "description": message,
                    }
                )

        for name, points, message in self.check_behavioral_patterns(profile):
            breakdown[name] = points
            score += points

            findings.append(
                {
                    "type": name,
                    "points": points,
                    "description": message,
                }
            )

        score = clamp_score(score)

        level = risk_level(score)

        return {
            "username": username,
            "platform": self.platform,
            "score": score,
            "risk_level": level,
            "flagged_as_high_risk": score >= 50,
            "finding_count": len(findings),
            "score_breakdown": breakdown,
            "findings": findings,
        }

    def analyze_batch(
        self,
        profiles: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Analyze multiple profiles."""

        results = []

        for profile in profiles:
            results.append(self.analyze(profile))

        return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def build_report(
    profiles: List[Dict[str, Any]],
    results: List[Dict[str, Any]],
    platform: str,
) -> Dict[str, Any]:
    """Build the final JSON report."""

    high_risk = sum(
        1
        for result in results
        if result["flagged_as_high_risk"]
    )

    return {
        "metadata": {
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "tool": "Day 09 Fake Profile & Bot Detector",
            "version": "1.0",
            "analysis_type": "rule_based_heuristic_analysis",
            "platform": platform,
            "profile_count": len(profiles),
        },
        "summary": {
            "total_profiles": len(results),
            "high_risk_profiles": high_risk,
            "low_or_medium_risk_profiles": len(results) - high_risk,
        },
        "results": results,
        "limitations": [
            "The score is a risk indicator, not proof that an account is fake.",
            "Individual heuristics can produce false positives.",
            "Legitimate new accounts may appear suspicious because of account age.",
            "Legitimate users may have unusual follower/following ratios.",
            "No social-media platform API or external account data is accessed.",
            "Human verification and additional evidence are required before concluding impersonation or bot activity.",
        ],
    }


def save_report(
    report: Dict[str, Any],
    output_path: Path,
) -> None:
    """Save structured JSON evidence."""

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False,
        )

    logger.info(
        "Report saved to: %s",
        output_path.resolve(),
    )


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

def print_results(results: List[Dict[str, Any]]) -> None:
    """Print human-readable results."""

    print()
    print("=" * 72)
    print("🎭 DAY 09 — FAKE PROFILE & BOT DETECTOR")
    print("=" * 72)

    print()

    for index, result in enumerate(results, start=1):
        print(
            f"[{index}] {result['username']}"
        )

        print(
            f"    Score       : "
            f"{result['score']}/100"
        )

        print(
            f"    Risk Level  : "
            f"{result['risk_level']}"
        )

        print(
            f"    Findings    : "
            f"{result['finding_count']}"
        )

        if result["findings"]:
            for finding in result["findings"]:
                print(
                    f"      - +{finding['points']} "
                    f"{finding['description']}"
                )

        print()

    high_risk = sum(
        1
        for result in results
        if result["flagged_as_high_risk"]
    )

    print("-" * 72)
    print(f"Total profiles : {len(results)}")
    print(f"High-risk      : {high_risk}")
    print(f"Low/medium     : {len(results) - high_risk}")
    print("=" * 72)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Day 09 — Rule-based social-media fake profile "
            "and bot-risk detector."
        )
    )

    parser.add_argument(
        "--platform",
        "-p",
        choices=[
            "twitter",
            "instagram",
            "facebook",
            "linkedin",
        ],
        default=DEFAULT_PLATFORM,
        help="Platform profile type being analyzed.",
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help="Analyze built-in demonstration profiles.",
    )

    parser.add_argument(
        "--file",
        type=Path,
        help="Path to a JSON file containing profile data.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=(
            f"Output JSON report "
            f"(default: {DEFAULT_OUTPUT})"
        ),
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Application entry point."""

    args = parse_arguments()

    if args.demo and args.file:
        logger.error(
            "Use either --demo or --file, not both."
        )
        sys.exit(1)

    if not args.demo and not args.file:
        logger.error(
            "Provide --demo or --file."
        )
        sys.exit(1)

    try:
        if args.demo:
            profiles = DEMO_PROFILES

        else:
            profiles = load_profiles(args.file)

        if not profiles:
            logger.error("No profiles were supplied.")
            sys.exit(1)

        logger.info(
            "Starting fake-profile analysis"
        )

        logger.info(
            "Platform: %s",
            args.platform,
        )

        logger.info(
            "Profiles: %d",
            len(profiles),
        )

        analyzer = FakeProfileAnalyzer(
            platform=args.platform
        )

        results = analyzer.analyze_batch(
            profiles
        )

        report = build_report(
            profiles=profiles,
            results=results,
            platform=args.platform,
        )

        save_report(
            report,
            args.output,
        )

        print_results(results)

        print()
        print(
            f"[+] JSON report: "
            f"{args.output.resolve()}"
        )

        print()
        print("✅ Analysis complete.")

    except ValueError as exc:
        logger.error("%s", exc)
        sys.exit(1)

    except KeyboardInterrupt:
        print("\n[!] Analysis interrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
