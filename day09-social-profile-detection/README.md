# Day 09 — Social Media Impersonation & Fake Profile Detection

## Overview

Day 09 of the Sqrock Cybersecurity Internship — Phase 1.

This project implements a Python-based fake-profile and bot detection simulator using behavioral heuristics.

The tool evaluates synthetic Twitter/X-like profile data and produces a risk score based on characteristics commonly associated with suspicious, automated, or impersonating accounts.

This project is designed for cybersecurity awareness, defensive analysis, and authorized laboratory testing.

---

## Objective

Detect potentially fake, automated, or impersonating social-media profiles using behavioral indicators.

The detector does not attempt to access or scrape real social-media accounts.

All demonstration profiles are synthetic laboratory data.

---

## Detection Heuristics

The analyzer evaluates multiple profile characteristics, including:

- Account age
- Follower/following ratio
- Profile-picture availability
- Post count
- Generic/default bio indicators
- Generic/default display-name indicators
- Verification status
- Engagement rate
- Follower growth rate
- Posting consistency
- Language consistency
- Hashtag usage
- Mention usage
- Reply behavior
- Original-content indicators
- Copy-paste behavior
- Potential impersonation indicators

The individual heuristic findings are combined into a score from `0` to `100`.

---

## Risk Levels

| Score | Risk Level |
|---:|---|
| 0–29 | LOW |
| 30–49 | MEDIUM |
| 50–69 | HIGH |
| 70–100 | CRITICAL |

The score represents a heuristic risk assessment.

It does **not** prove that an account is fake.

A legitimate account can trigger individual indicators, while a sophisticated fake account may avoid them.

---

## Project Structure

```text
day09-social-profile-detection/
├── fake_profile_detector.py
├── input/
│   └── profiles.json
├── output/
│   └── fake_profile_results.json
├── report/
│   └── day09-report.md
├── screenshots/
│   ├── demo-analysis.png
│   ├── file-input-analysis.png
│   └── json-report.png
├── README.md
└── requirements.txt

Requirements
Python 3
colorama

Install the dependency:

pip install -r requirements.txt
Usage
Run the built-in demonstration
python3 fake_profile_detector.py --demo
Specify the platform
python3 fake_profile_detector.py \
  --platform twitter \
  --demo

Supported platforms:

twitter
instagram
facebook
linkedin

The current laboratory dataset uses Twitter/X-like profile fields.

Analyze a JSON Input File

Synthetic profile data can be supplied through:

python3 fake_profile_detector.py \
  --platform twitter \
  --file input/profiles.json

The input file contains multiple synthetic profiles representing different behavioral patterns.

Example Profile Data

A simplified profile can contain fields such as:

{
  "username": "example_user",
  "name": "Example User",
  "account_age_days": 120,
  "followers": 500,
  "following": 300,
  "posts": 200,
  "no_profile_pic": false,
  "default_bio": false,
  "default_name": false,
  "verified": false,
  "engagement_rate": 2.5,
  "follower_growth_rate": 3.0
}
Output

The analyzer generates:

output/fake_profile_results.json

The JSON report contains:

Analysis timestamp
Platform
Number of profiles analyzed
Risk scores
Risk levels
Individual findings
Profile identifiers
Detection results
Example Results

The demonstration dataset contains four synthetic profiles representing different behavioral patterns.

Expected behavior includes:

realsara
Score: 0/100
Risk Level: LOW

A highly suspicious bot-style profile produces a substantially higher score:

botty_mcbotface
Score: 100/100
Risk Level: CRITICAL

Other synthetic profiles demonstrate suspicious growth, follower/following imbalance, low activity, and impersonation indicators.

Exact results are recorded in the generated JSON evidence.

Defensive Interpretation

The detector should be treated as a triage tool rather than a definitive classifier.

A high score means that multiple suspicious indicators were observed.

It does not independently establish:

That an account is operated by a bot
That an account is malicious
That an account belongs to an impersonator
That a person behind the account is conducting an attack

Additional verification would be required before taking enforcement action.

Security and Ethical Scope

This project is intentionally limited to synthetic profile data.

It does not:

Scrape social-media platforms
Bypass authentication
Collect private information
Attempt account takeover
Send messages to targets
Automate interaction with real accounts

The purpose is to demonstrate defensive social-engineering awareness and behavioral analysis.

Screenshots / Evidence

Recommended evidence includes:

Demo detector execution
File-based profile analysis
Generated JSON report

Screenshots should show the terminal output and generated evidence without exposing personal information.

Learning Outcomes

This exercise demonstrates:

Behavioral heuristic design
Risk scoring
Feature-based analysis
Synthetic data generation
JSON input/output
CLI argument handling
Defensive OSINT concepts
Social-engineering awareness
Limitations of heuristic detection
Limitations

The detector uses manually selected heuristics rather than a trained machine-learning model.

Indicators such as:

Account age
Follower ratios
Missing profile pictures
Low engagement
Generic bios

are not inherently malicious.

Therefore, the resulting score should be considered an investigative signal rather than proof of malicious activity.

Internship Task

Phase 1 — Day 09

Topic: Social Media Impersonation & Fake Profile Detection

Objective: Detect fake/bot social profiles using behavioral heuristics.

Implementation: Python-based synthetic profile scoring simulator.
