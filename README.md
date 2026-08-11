# Cybersecurity Internship — Phase 1

A practical cybersecurity internship portfolio documenting hands-on security labs, Python tooling, Linux practice, technical analysis, and security awareness exercises.

> **Status:** Phase 1 in progress

## About This Repository

This repository contains my practical work throughout the cybersecurity internship.

The objective is not only to complete the assigned tasks, but to understand the underlying security concepts, implement them in controlled environments, document the methodology, and develop responsible cybersecurity practices.

All testing is performed against authorized targets, local laboratory infrastructure, or intentionally provided training environments.

## Environment

* Parrot OS
* Python 3
* Git / GitHub
* Apache HTTP Server
* Linux command line
* `jq`
* Python virtual environments

## Phase 1 Progress

| Day | Topic                                      | Status     |
| --- | ------------------------------------------ | ---------- |
| 01  | OSINT & Passive Reconnaissance             | ✅ Complete |
| 02  | Email Harvesting & Social Engineering Prep | ✅ Complete |
| 03  | Upcoming                                   | ⏳          |
| 04  | Upcoming                                   | ⏳          |
| 05  | Upcoming                                   | ⏳          |

## Day 01 — OSINT & Passive Reconnaissance

Developed a Python-based passive intelligence collection tool capable of aggregating publicly available information from multiple sources.

### Concepts Practiced

* Open-Source Intelligence (OSINT)
* Passive reconnaissance
* WHOIS
* DNS
* IPv4 / IPv6 resolution
* IP geolocation
* Passive host intelligence
* Passive subdomain discovery
* Third-party API interaction
* JSON reporting
* Error handling
* Concurrent information gathering

### Project

[`day01-osint/`](./day01-osint/)

The project contains the scanner source code, requirements, documentation, screenshots, and sanitized/public-safe reporting artifacts.

## Day 02 — Email Harvesting & Social Engineering Awareness

Built a Python-based email harvesting tool for an intentionally created local Apache laboratory environment.

### Concepts Practiced

* HTTP requests
* HTML retrieval
* Regular expressions
* Email extraction
* Deduplication
* Role-based email classification
* Security awareness
* Pretexting fundamentals
* Defensive email security
* SPF
* DKIM
* DMARC
* Error handling
* Structured JSON reporting

### Laboratory Environment

Testing was performed against a locally hosted Apache environment using:

```text
127.0.0.1
```

This ensured that the exercise remained within the controlled laboratory environment.

### Project

[`day02-email-harvesting/`](./day02-email-harvesting)

## Ethical Boundaries

This repository is intended for educational and authorized cybersecurity work.

The following principles are followed throughout the internship:

* Do not perform unauthorized reconnaissance.
* Do not attempt to access systems without permission.
* Do not exploit third-party infrastructure without authorization.
* Do not publish credentials, tokens, passwords, or private information.
* Do not unnecessarily publish sensitive reconnaissance data.
* Use local laboratories and intentionally authorized training targets whenever possible.
* Treat third-party intelligence as potentially incomplete, stale, or approximate.
* Distinguish observations from verified conclusions.

## Repository Structure

```text
cyber-internship/
│
├── README.md
├── .gitignore
│
├── day01-osint/
│   ├── README.md
│   ├── osint_scanner.py
│   ├── requirements.txt
│   ├── output/
│   ├── report/
│   └── screenshots/
│
├── day02-email-harvesting/
│   ├── README.md
│   ├── email_harvester.py
│   ├── requirements.txt
│   ├── output/
│   ├── report/
│   └── screenshots/
│
└── future-days/
```

## Learning Philosophy

The goal of this internship is not simply to run tools.

For every exercise, I aim to understand:

1. What the technology does.
2. How it works internally.
3. What information it provides.
4. What its limitations are.
5. How the results should be interpreted.
6. How the technique can be used responsibly.
7. How the work can be reproduced and documented.

## Progress

This repository will be updated throughout the internship as new labs, tools, reports, and lessons are completed.

**Phase 1 — In Progress**
