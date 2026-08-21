# Day 10 — Baiting & Watering Hole Attack Simulation

**Sqrock Cybersecurity Internship — Phase 1**

## Overview

Day 10 demonstrates the detection and logging side of **baiting** and **watering-hole attacks** through a controlled local honeypot simulation.

The project implements a lightweight Python HTTP honeypot that exposes predefined bait URLs and records requests made to those URLs.

This is an **awareness and defensive simulation only**. No real malware, payload delivery, exploitation, credential collection, or external target interaction is performed.

---

## Objective

Understand how defenders can detect interaction with suspicious bait links by building a local honeypot that records:

- Timestamp
- Source IP address
- HTTP method
- Requested path
- User-Agent
- Whether the requested path matched a configured bait link

---

## Concepts Demonstrated

### Baiting

Baiting attempts to attract a user through something enticing or interesting, such as:

- Free software
- Important documents
- Fake updates
- Free downloads
- Other attractive resources

The objective is to encourage the victim to interact with the bait.

### Watering Hole

A watering-hole attack involves compromising or manipulating a website that a particular target group is likely to visit.

In this lab, no real website is compromised.

Instead, the local honeypot represents a controlled defensive environment where suspicious links can be monitored.

---

## Lab Architecture

```text
                    Local Test Client
                          |
                          | HTTP GET
                          v
              +------------------------+
              |  Local Honeypot        |
              |  127.0.0.1:8080        |
              +------------------------+
                          |
                          v
                Bait Path Detection
                          |
             +------------+------------+
             |                         |
          Normal                    Bait
          Request                  Trigger
             |                         |
             +------------+------------+
                          |
                          v
                  Event Logging
                    /          \
                   v            v
              JSON Report    TXT Report
Project Structure
day10-baiting-watering-hole/
├── honeypot_tracker.py
├── input/
│   └── bait_links.json
├── output/
│   ├── honeypot_events.json
│   └── honeypot_events.txt
├── README.md
├── report/
│   └── day10-report.md
├── requirements.txt
└── screenshots/
    └── honeypot-server-events.png
Bait Links

The configured bait paths are stored in:

input/bait_links.json

Current test paths:

/free-download
/important-document
/software-update
/bait

These are harmless local routes and do not point to real downloads or malicious resources.

Requirements
Python 3
Linux/Parrot OS recommended for the internship environment

The honeypot uses Python's standard library, so no third-party package is required.

Running the Honeypot

From the project directory:

python3 honeypot_tracker.py

The server listens on:

http://127.0.0.1:8080

The default configuration intentionally binds to the loopback interface so that the lab remains local.

Command-Line Options

Display help:

python3 honeypot_tracker.py --help

Run on a different local port:

python3 honeypot_tracker.py --port 8081

Specify the host explicitly:

python3 honeypot_tracker.py --host 127.0.0.1 --port 8080
Testing the Honeypot

Open a second terminal while the honeypot is running.

Test a normal request:

curl http://127.0.0.1:8080/

Test configured bait paths:

curl http://127.0.0.1:8080/free-download
curl http://127.0.0.1:8080/software-update
curl http://127.0.0.1:8080/bait

The honeypot records each request and identifies whether the requested path matches a configured bait link.

Logged Data

Each event contains:

timestamp
ip
method
path
user_agent
bait_triggered

Example:

{
    "timestamp": "2026-08-21T06:23:14.872601+00:00",
    "ip": "127.0.0.1",
    "method": "GET",
    "path": "/free-download",
    "user_agent": "curl/8.14.1",
    "bait_triggered": true
}
Output Files
JSON
output/honeypot_events.json

Machine-readable event data suitable for further analysis or SIEM-style processing.

Text
output/honeypot_events.txt

Human-readable event log for quick inspection and reporting.

Observed Test Results

The completed local test generated four HTTP events:

Event	Path	Source	Bait Triggered
1	/	127.0.0.1	No
2	/free-download	127.0.0.1	Yes
3	/software-update	127.0.0.1	Yes
4	/bait	127.0.0.1	Yes

The test therefore demonstrated:

Normal request detection
Bait-path matching
Source IP logging
User-Agent logging
JSON event generation
Human-readable event generation
Security Lessons

The simulation demonstrates why defenders monitor suspicious links and web requests.

Potential defensive controls include:

Secure web filtering
Endpoint protection
Script blocking
Browser security controls
Patch management
User awareness training
DNS/web reputation filtering
Network monitoring
Honeypots and deception systems
Ethical Scope

This project is intentionally limited to a local defensive simulation.

No:

Real websites were compromised
Malware was delivered
Drive-by downloads were performed
Credentials were collected
Personal information was harvested
External targets were contacted

All testing was performed against:

127.0.0.1
Evidence

The screenshots/ directory contains evidence of the local honeypot execution and captured events.

Primary evidence:

screenshots/honeypot-server-events.png
Conclusion

The Day 10 lab successfully demonstrated a basic honeypot-based approach to detecting bait-link interaction.

The simulator identified configured bait paths and recorded useful request metadata including timestamp, source IP, HTTP method, requested path, and User-Agent.

The exercise reinforces the defensive value of monitoring suspicious user interaction and using controlled deception systems to improve security awareness and detection.
