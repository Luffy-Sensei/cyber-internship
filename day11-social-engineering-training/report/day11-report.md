# Executive Report: Social Engineering Awareness Training Engine

## 1. Executive Summary

This report details the implementation, architecture, and deployment of an interactive Command-Line Interface (CLI) Social Engineering Awareness Training Engine developed in Python. While technical security controls (e.g., Secure Email Gateways, Firewalls, Endpoint Detection & Response) filter out a high percentage of automated cyber threats, the human element remains a primary attack surface targeted via social engineering.

The primary objective of this module is to strengthen organizational security posture by delivering realistic scenario-based training directly within a developer/analyst workflow. The engine dynamically ingests scenario data, evaluates user decision-making across five core threat vectors, enforces real-time pedagogical feedback loops, and exports audit-compliant telemetry logs (`.json`, `.txt`, and `.log`) to record performance metrics.

---

## 2. Threat Vectors & Defensive Analysis

The training module evaluates user decision-making against five primary threat vectors encountered in modern enterprise environments:

| Threat Vector | Attack Scenario / Pretext | Risk Identification Factor | Prescribed Defensive Action |
| --- | --- | --- | --- |
| **Phishing** | Urgency-driven email requesting password reset via an embedded URL. | Suspicious domain, high-pressure tactic, credential demand. | Do not click the link; report the email to SOC/IT; verify via official channels. |
| **USB Baiting** | Dropped physical media placed in common office areas. | Unlabeled or suspicious hardware media. | Do not insert into host system; hand media directly to Physical Security or IT. |
| **Vishing (Voice)** | Phone call from impersonated IT support requesting 2FA/OTP code. | Out-of-band request for secret authentication tokens. | Never share OTP codes; hang up immediately; contact IT via verified extensions. |
| **SOCMINT Profiling** | Unverified social media contact requesting internal technical architecture. | Reconnaissance targeting internal stack and infrastructure. | Refuse disclosure of internal infrastructure; verify contact identity out-of-band. |
| **Credential Hygiene** | Reusing passwords across corporate and personal web accounts. | Vulnerability to credential stuffing following third-party breaches. | Enforce unique passwords per account; utilize enterprise password managers. |

---

## 3. Tool Architecture & System Design

The application utilizes a decoupled, modular design to ensure scalable question management and clean telemetry processing.

```
                   ┌──────────────────────────────┐
                   │     input/questions.json     │
                   └──────────────┬───────────────┘
                                  │ (JSON Ingestion)
                                  ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │                      se_awareness_quiz.py                        │
 │                                                                  │
 │  • Question Ingestion Engine & Schema Validator                   │
 │  • Input Normalizer (.strip().upper())                           │
 │  • Scoring Logic & Real-time Explanatory Feedback Loop           │
 │  • Logging Handler (File & Console Streams)                      │
 └────────────────────────────────┬─────────────────────────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         │                        │                        │
         ▼                        ▼                        ▼
┌──────────────────┐    ┌───────────────────┐    ┌──────────────────┐
│ output/quiz.log  │    │ quiz_results.json │    │ quiz_results.txt │
│ (Runtime Traces) │    │ (SIEM Telemetry)  │    │ (Human Readable) │
└──────────────────┘    └───────────────────┘    └──────────────────┘

```

### Module Breakdown

* **`se_awareness_quiz.py`**: The main driver program containing the application logic, menu navigation, input sanitization routines, scoring engine, and multi-file logger.
* **`input/questions.json`**: The input data store containing array-indexed scenario dictionaries with questions, options, correct answers, and pedagogical feedback strings.
* **`output/` Directory**: Storage location for output artifacts generated after assessment completion:
* `quiz.log`: Append-only event logging tracking application boot time, question cycles, user choices, and error exceptions.
* `quiz_results.json`: Structured result metrics export containing execution timestamps, individual score breakdowns, percentage accuracy, and pass/fail indicators suitable for SIEM/data platform ingestion.
* `quiz_results.txt`: Human-readable summary report summarizing the completed assessment session.



---

## 4. Execution & Verification Workflow

### Test Execution Steps

1. **Environment Initialization:**
```bash
cd ~/cyber-internship/day11-social-engineering-training
source ../venv/bin/activate
pip install -r requirements.txt

```


2. **Interactive Run:**
```bash
python3 se_awareness_quiz.py

```


3. **Artifact Verification:**
```bash
ls -la output/
cat output/quiz_results.json

```



### Execution Evidence

Assessment execution evidence was captured and validated in the `screenshots/` directory:

* **`screenshots/quiz-start.png`**: Startup banner and question loading phase.
* **`screenshots/quiz-feedback.png`**: Immediate feedback output following answer selection.
* **`screenshots/quiz-results.png`**: Score summary output display.
* **`screenshots/json-report.png`**: Exported structured telemetry format in `output/quiz_results.json`.

---

## 5. Defensive Metrics & Strategic Recommendations

### Performance Metrics Target

* **Passing Threshold:** Set at $\ge 80\%$ (minimum 4 out of 5 scenarios correct).
* **Target Metric:** Reduce organizational phishing/vishing click rates by providing immediate feedback on incorrect selections.

### Strategic Recommendations

1. **Automated SIEM Integration:** Programmatically aggregate `output/quiz_results.json` files across organizational departments into centralized logging systems (e.g., Splunk, Elastic) to identify recurring vulnerability trends.
2. **Targeted Re-Training:** Users scoring below the 80% threshold should automatically be enrolled in follow-up micro-simulations focusing on their specific weak vectors.
3. **Continuous Scenario Updates:** Regularly update `input/questions.json` with emerging pretexts (e.g., AI voice cloning, QR code phishing/quishing) to keep training aligned with evolving threat tactics.
