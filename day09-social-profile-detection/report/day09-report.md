# Day 09 Report — Social Media Impersonation & Fake Profile Detection

## Internship

**Program:** Sqrock Cybersecurity Internship
**Phase:** Phase 1
**Day:** 09
**Topic:** Social Media Impersonation & Fake Profile Detection
**Environment:** Parrot OS VM
**Language:** Python 3

---

## 1. Objective

The objective of Day 09 was to understand how suspicious social-media accounts can be identified using behavioral heuristics.

The laboratory implementation evaluates synthetic Twitter/X-like profile data and assigns a risk score based on multiple suspicious characteristics.

The project focuses on defensive analysis and social-engineering awareness.

---

## 2. Background

Fake and automated social-media profiles can be used to establish trust before attempting social-engineering attacks.

Potential indicators include:

- Very new accounts
- Unusual follower/following ratios
- Missing profile pictures
- Very low activity
- Generic profile information
- Abnormally high growth
- Low engagement
- Inconsistent posting behavior
- Excessive hashtags or mentions
- Repeated or copied content
- Potential impersonation indicators

No single indicator is sufficient to determine that an account is fake.

The project therefore combines multiple indicators into a single heuristic risk score.

---

## 3. Implementation

The Python detector accepts synthetic profile data and evaluates each profile using weighted heuristics.

The resulting score is constrained to a range of:

```text
0–100
Risk levels are assigned according to the resulting score.

Score	Risk
0–29	LOW
30–49	MEDIUM
50–69	HIGH
70–100	CRITICAL

The detector also records individual findings explaining why a profile received its score.

4. Detection Features

The implementation evaluates indicators including:

Account age
Follower/following ratio
Profile-picture availability
Post count
Generic/default bio
Generic/default display name
Verification status
Engagement rate
Follower growth
Posting consistency
Language consistency
Hashtag ratio
Mention ratio
Reply ratio
Original-content indicators
Copy-paste behavior
Impersonation indicators

These indicators are intended for triage and awareness rather than definitive classification.

5. Test Dataset

The demonstration dataset contains four synthetic profiles.

Profile 1 — realsara

This profile represents a relatively established and normally behaving account.

Observed characteristics include:

Long account age
Large follower count
Reasonable following count
High post count
Profile picture
Normal engagement
Normal follower growth
Consistent posting
Original content

Observed result:

Score: 0/100
Risk Level: LOW
Profile 2 — botty_mcbotface

This synthetic profile represents a strongly suspicious bot-like account.

Observed indicators include:

Account less than one week old
2 followers versus 900 following
No profile picture
One post
Generic bio
Generic name
Very low engagement
Inconsistent posting
Inconsistent language usage
Excessive hashtags
Excessive mentions
Excessive replies
No original content
Copy-paste behavior

Observed result:

Score: 100/100
Risk Level: CRITICAL
Profile 3 — crypto_lover

This synthetic profile demonstrates a suspicious promotional account.

Observed indicators include:

New account
Elevated following/follower ratio
No profile picture
High follower growth
Inconsistent posting
High hashtag usage

Observed result:

Score: 77/100
Risk Level: CRITICAL
Profile 4 — sara_johnson_official

This synthetic profile demonstrates an impersonation-style scenario.

Observed indicators include:

New account
Very high following/follower ratio
No profile picture
Low post count
Generic profile information
Very low engagement
High follower growth
Inconsistent posting
No original content
Potential impersonation indicator

Observed result:

Score: 100/100
Risk Level: CRITICAL
6. Demonstration Execution

The built-in demonstration was executed using:

python3 fake_profile_detector.py --demo

The detector successfully analyzed four synthetic profiles and generated the JSON report.

A second execution was performed with explicit platform selection:

python3 fake_profile_detector.py \
  --platform twitter \
  --demo

The same synthetic dataset was successfully processed.

7. File-Based Testing

The detector also supports loading profiles from a JSON file.

The test dataset is stored at:

input/profiles.json

The analysis command is:

python3 fake_profile_detector.py \
  --platform twitter \
  --file input/profiles.json

The JSON file contains synthetic laboratory profiles only.

No real social-media account information is used.

8. Output Evidence

The detector generates:

output/fake_profile_results.json

The output records the analysis results, including:

Profile identifiers
Risk score
Risk level
Detection findings
Analysis metadata

This provides machine-readable evidence that can be reviewed after execution.

9. Security Significance

Fake-profile detection can support defensive social-engineering analysis.

Organizations can use behavioral indicators to identify accounts that may require additional verification before employees interact with them.

Potential defensive actions include:

Verify unexpected identities through another trusted communication channel
Avoid sharing sensitive information with suspicious accounts
Report suspected impersonation
Review account history before establishing trust
Treat unusual requests with caution
Use organizational awareness training to teach employees common social-engineering indicators
10. Limitations

This project is a heuristic simulator.

A high score does not prove that an account is fake.

For example:

New legitimate users can have young accounts.
Legitimate users may have few followers.
Some legitimate accounts may not have profile pictures.
Popular users may have unusual follower/following ratios.
Some users may rarely post.
Automated-looking behavior can sometimes be legitimate.

Conversely, sophisticated malicious accounts may intentionally avoid obvious indicators.

Therefore, the detector should be used as a triage mechanism, not as an automated final decision system.

11. Ethical Scope

The project uses synthetic data and does not interact with real social-media accounts.

The implementation does not:

Scrape real profiles
Attempt account takeover
Collect private information
Send messages
Automate social-media interaction
Bypass authentication
Target real individuals

The exercise is limited to authorized cybersecurity education and defensive analysis.

12. Evidence Collected

The following evidence is recommended for the Day 09 submission:

screenshots/
├── demo-analysis.png
├── file-input-analysis.png
└── json-report.png
demo-analysis.png

Shows successful execution of:

python3 fake_profile_detector.py --demo
file-input-analysis.png

Shows successful JSON-file analysis:

python3 fake_profile_detector.py \
  --platform twitter \
  --file input/profiles.json
json-report.png

Shows the generated:

output/fake_profile_results.json
13. Learning Outcomes

This exercise demonstrated:

Behavioral heuristic design
Risk scoring
Feature-based profile analysis
Synthetic security datasets
JSON input/output
CLI argument handling
Social-engineering awareness
Impersonation detection concepts
Bot-behavior indicators
Limitations of heuristic classification
14. Conclusion

Day 09 successfully implemented a Python-based fake-profile and bot detection simulator.

The detector successfully distinguished between synthetic low-risk and high-risk behavioral patterns and produced detailed findings explaining the resulting scores.

The exercise demonstrates how multiple weak indicators can be combined into a defensive risk-assessment model while emphasizing that heuristic scoring should not be treated as definitive proof of malicious activity.

Day 09 Status: COMPLETE
