# Day 02 — Email Harvesting & Security Awareness

**Cybersecurity Internship — Phase 1**

## Overview

Day 02 focuses on email harvesting and the security implications of publicly exposed email addresses.

The objective was to understand how email addresses can be discovered from publicly accessible webpage content, while maintaining a strict ethical boundary by performing all testing against a locally hosted Apache laboratory environment.

The project implements a Python-based email extraction tool that retrieves an authorized webpage, extracts email-like strings using regular expressions, normalizes and deduplicates the results, performs conservative security-awareness classification, and generates a structured JSON report.

## Learning Objectives

* Understand the concept of email harvesting.
* Understand why publicly accessible information is not automatically authorized for automated collection.
* Understand regex-based email extraction.
* Understand normalization and deduplication.
* Distinguish syntactic email discovery from mailbox verification.
* Understand basic social-engineering exposure.
* Understand the defensive role of SPF, DKIM, and DMARC.
* Practice Python HTTP requests, error handling, CLI arguments, and JSON reporting.
* Practice Linux-based cybersecurity tooling on Parrot OS.

## Lab Environment

| Component        | Details                 |
| ---------------- | ----------------------- |
| Operating System | Parrot OS               |
| Web Server       | Apache HTTP Server      |
| Target           | Localhost (`127.0.0.1`) |
| Language         | Python 3                |
| HTTP Library     | Requests                |
| Output Format    | JSON                    |
| JSON Processor   | jq                      |

All testing was performed against a locally controlled laboratory environment.

## Tool Features

The email harvesting tool provides:

1. HTTP/HTTPS URL validation.
2. Controlled webpage retrieval.
3. Regex-based email extraction.
4. Lowercase normalization.
5. Duplicate removal.
6. Conservative role-based classification.
7. Security-awareness observations.
8. Structured JSON reporting.
9. HTTP and input error handling.
10. Configurable report output paths.

## Workflow

```text
Authorized URL
     │
     ▼
URL Validation
     │
     ▼
HTTP GET Request
     │
     ▼
Retrieve HTML
     │
     ▼
Regex Email Extraction
     │
     ▼
Normalize + Deduplicate
     │
     ▼
Security Awareness Analysis
     │
     ▼
JSON Report
```

## Example Execution

```bash
python3 email_harvester.py \
http://127.0.0.1/cyber-lab/contact.html
```

The default report is written to:

```text
output/email_harvest_report.json
```

The JSON report can be inspected using:

```bash
jq . output/email_harvest_report.json
```

## Testing

The tool was tested against a controlled Apache laboratory page containing:

* Normal email addresses
* Duplicate addresses
* Uppercase email addresses
* Multi-label domains
* `mailto:` links
* Malformed email-like strings
* Invalid URLs
* Nonexistent HTTP resources

Testing verified extraction, normalization, deduplication, validation, and error handling.

## Security Considerations

An extracted email address does not prove that:

* The mailbox exists.
* The mailbox is active.
* The address belongs to an individual.
* The address can receive email.
* The address represents an authorized communication channel.

The project therefore uses conservative terminology such as **role-based address** and **unclassified address** instead of assuming the identity or ownership of an address.

## Defensive Awareness

Publicly exposed email addresses can increase exposure to:

* Phishing
* Impersonation
* Social engineering
* Email spoofing attempts

Defensive measures include:

* SPF
* DKIM
* DMARC
* Multi-factor authentication
* Phishing-resistant authentication
* Security-awareness training
* Appropriate protection of publicly exposed organizational accounts

These controls reduce risk but do not eliminate social-engineering or phishing threats.

## Ethical Boundary

This project was developed for authorized cybersecurity training.

Testing was intentionally performed against:

```text
127.0.0.1
```

Using a locally controlled environment prevents accidental interaction with third-party systems and allows security concepts to be tested safely.

No credentials, private information, or unauthorized third-party data are intentionally collected or published.

## Skills Practiced

* Python
* Regular expressions
* HTTP fundamentals
* Linux
* Apache
* CLI development
* JSON
* `jq`
* Error handling
* Security awareness
* Ethical cybersecurity methodology
* Technical documentation

## Project Status

**Day 02 — Complete**

Core implementation, laboratory testing, error handling, structured reporting, and documentation completed.
