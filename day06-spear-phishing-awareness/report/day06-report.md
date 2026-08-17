# Day 06 — Spear Phishing Awareness

## Overview

**Phase:** Phase 1
**Day:** 06
**Topic:** Spear Phishing Email Craft
**Difficulty:** Intermediate
**Project:** Cybersecurity Internship

## Objective

Build a Python-based spear-phishing awareness engine that generates a personalized training scenario and analyzes the social-engineering techniques contained within it.

The engine combines target-profile information with a simulated security notification and produces structured defensive analysis.

## Implementation

The project was implemented in:

```text
spear_phishing_generator.py

The generator produces two report formats:

output/awareness_scenarios.json
output/awareness_email.txt

The JSON report provides structured data for further analysis, while the text report provides a human-readable representation of the generated scenario.

Target Profile

The training scenario uses the following profile:

Field	Value
Name	Riya Sharma
Email	riya@company.com
Company	Sqrock
Location	Bangalore, India

The profile information is used to demonstrate how personalization can increase the credibility of a spear-phishing message.

Generated Email Scenario

Sender: IT Security <it-security@sqrock.example>
Recipient: riya@company.com
Subject: Action Required: Your Sqrock account will be disabled

The scenario uses:

Internal IT/security impersonation
A security-related pretext
A 24-hour deadline
A threat of account suspension
A personalized location reference
A verification request

The verification destination is represented by:

https://lab.internal/awareness-test
Psychological Triggers

The engine identified four psychological triggers.

Trigger	Severity	Defensive Focus
Authority	High	Verify the sender through independent channels
Urgency	High	Do not allow deadlines to bypass security procedures
Fear	Medium	Remain calm and follow established procedures
Personalization	Medium	Recognize that public information can be used to increase credibility
Red Flags

The generated analysis identified six phishing indicators:

Sender impersonation — The message presents itself as an IT/security communication.
Unexpected security notification — The recipient receives an unsolicited account-security message.
Urgency — A 24-hour deadline encourages rapid action.
Threat of consequences — Account suspension is presented as the consequence of non-compliance.
Verification request — The recipient is encouraged to follow a supplied verification path.
Personalized hook — Publicly observable information is used to increase credibility.
Defensive Guidance

The engine provides five defensive recommendations:

Verify suspicious requests through official internal channels.
Do not rely solely on a sender display name.
Avoid unexpected verification links.
Do not allow urgency to bypass normal security procedures.
Report suspicious messages through the organization's security process.
Email Authentication

The report includes three important email-security controls.

SPF

Sender Policy Framework helps identify whether the sending infrastructure is authorized to send email for a domain.

DKIM

DomainKeys Identified Mail uses cryptographic signatures to provide message authentication and integrity information associated with a domain.

DMARC

Domain-based Message Authentication, Reporting, and Conformance provides domain-alignment and policy mechanisms involving SPF and/or DKIM, along with reporting capabilities.

Email authentication controls improve protection against domain impersonation but do not eliminate every phishing technique.

Output Statistics

The generated JSON report contains:

Metric	Result
Psychological triggers	4
Red flags	6
Defensive guidance items	5
Authentication controls	3
Validation

The generated JSON was inspected with jq and contains valid structured JSON.

Validation command:

jq empty output/awareness_scenarios.json

Python syntax can be validated with:

python3 -m py_compile spear_phishing_generator.py

Repository formatting can be checked with:

git diff --check
Key Learning Outcomes

This task demonstrated:

How spear phishing differs from generic phishing
How OSINT-derived information can increase message personalization
How authority, urgency, fear, and personalization influence recipients
How to identify phishing indicators systematically
How defensive guidance can be attached to individual indicators
The role of SPF, DKIM, and DMARC in email security
How structured JSON can be used to represent security-awareness scenarios
How security-analysis tooling can produce both machine-readable and human-readable reports
Evidence

The project includes screenshots demonstrating:

Successful generator execution
Generated JSON report
Generated awareness email
Psychological trigger and red-flag analysis
Conclusion

Day 06 successfully produced a structured spear-phishing awareness scenario with personalized target information, psychological-trigger analysis, phishing red flags, defensive guidance, and email-authentication information.

The resulting artifacts provide both machine-readable JSON and a human-readable awareness report suitable for documenting the exercise.
