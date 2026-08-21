# Day 11: Interactive Social Engineering Awareness Training Engine

## Project Overview

This repository contains a production-ready, CLI-based **Social Engineering Awareness Training Engine** built in Python. Designed as part of a multi-day cybersecurity offensive/defensive training track, this tool focuses on strengthening the human layer of security—often considered the most targeted attack surface in modern enterprise environments.

The framework ingests scenario-based threat vectors from a modular JSON dataset, interacts with users via a terminal interface, delivers instant feedback on incorrect answers, and exports audit-ready telemetry logs (`.json`, `.txt`, and `.log`) for administrative tracking.

---

## Technical Architecture & Workflow

```
                        ┌──────────────────────────────┐
                        │    input/questions.json      │
                        │ (Scenario Threat Dataset)    │
                        └──────────────┬───────────────┘
                                       │
                                       ▼
 ┌───────────────────────────────────────────────────────────────────────────┐
 │                         se_awareness_quiz.py                              │
 │                                                                           │
 │  1. Ingests & Validates JSON Schema                                      │
 │  2. Sanitizes User Input (.strip().upper())                               │
 │  3. Evaluates Choices against Answer Key                                  │
 │  4. Triggers Immediate Pedagogical Feedback Loops                         │
 └──────────────┬──────────────────────────────┬─────────────────────────────┘
                │                              │
                ▼                              ▼
 ┌──────────────────────────────┐    ┌──────────────────────────────────────┐
 │       Terminal Display       │    │           output/ Directory          │
 │  - Real-time Q&A Interface   │    │  - quiz.log (Execution Traces)      │
 │  - Score Summary Output      │    │  - quiz_results.json (Structured)   │
 └──────────────────────────────┘    │  - quiz_results.txt (Plaintext)      │
                                     └──────────────────────────────────────┘

```

---

## Threat Vectors Evaluated

The assessment dataset evaluates user readiness across five primary social engineering vectors:

* **Phishing:** Identifying deceptive email indicators, urgent domain spoofs, and credential harvesting links.
* **USB Baiting:** Recognizing the threat of untrusted physical media dropped in common corporate areas.
* **Vishing (Voice Phishing):** Handling high-pressure phone calls demanding sensitive One-Time Passwords (OTPs) or credentials.
* **SOCMINT / Impersonation:** Spotting fake executive/recruiter profiles gathering reconnaissance on internal architecture.
* **Credential Hygiene:** Mitigating password reuse risk and preventing credential stuffing attacks.

---

## Directory Structure

```
.
├── input/
│   └── questions.json          # Modular JSON dataset storing threat scenarios
├── output/
│   ├── quiz.log                # System execution logs and runtime traces
│   ├── quiz_results.json       # Exported structured assessment results
│   └── quiz_results.txt        # Formatted plaintext scorecard summary
├── __pycache__/
│   └── se_awareness_quiz.cpython-313.pyc
├── README.md                   # Project documentation
├── report/
│   └── day11-report.md         # Detailed executive & technical report
├── requirements.txt            # Environment dependency list
├── screenshots/                # Visual proof of execution
│   ├── json-report.png         # Exported JSON structure snippet
│   ├── quiz-feedback.png       # Instant explanation response screenshot
│   ├── quiz-results.png        # Terminal score output
│   └── quiz-start.png          # Initial menu startup screen
└── se_awareness_quiz.py        # Core Python CLI quiz application script

```

---

## Key Technical Features

* **Modular Data Ingestion:** Questions and explanations are decoupled from code logic and read directly from `input/questions.json`.
* **Robust Input Handling:** Accepts case-insensitive inputs (`a`, `b`, `c`) and strips trailing whitespace to prevent user error.
* **Immediate Feedback Loops:** Prints detailed contextual explanations right after an answer is submitted to maximize learning retention.
* **Multi-Format Telemetry Export:** Automatically writes completion timestamps, question-by-question breakdowns, percentage scores, and pass/fail statuses into raw JSON and text files for SIEM ingestion or audit logging.

---

## Quickstart & Execution Guide

### 1. Prerequisites & Environment Setup

Navigate to the project directory and ensure your virtual environment is active:

```bash
cd ~/cyber-internship/day11-social-engineering-training
source ../venv/bin/activate
pip install -r requirements.txt

```

### 2. Running the Training Engine

Execute the Python script directly from your terminal:

```bash
python3 se_awareness_quiz.py

```

### 3. Reviewing Output Artifacts

Once completed, check the generated telemetry files:

```bash
cat output/quiz_results.txt
cat output/quiz_results.json
cat output/quiz.log

```

---

## Visual Demonstration

| Startup Screen | Real-Time Feedback Loop |
| --- | --- |
|  |  |

| Final Scorecard | Exported JSON Telemetry |
| --- | --- |
|  |  |

---
