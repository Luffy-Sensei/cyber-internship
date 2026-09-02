# Day 24 — Automated Threat Intelligence IP Blocking Pipeline

A controlled Python security lab that demonstrates how threat-intelligence indicators can be ingested, validated, evaluated against risk-based policies, and translated into **firewall block proposals** through a safe **DRY-RUN** adapter.

This project intentionally does **not** modify the host firewall. It is designed for cybersecurity training, defensive engineering practice, security automation, validation testing, and audit evidence generation.

---

## 1. Objective

Build an automated threat-intelligence processing pipeline that can:

* Ingest structured threat-intelligence indicators.
* Validate IP addresses, indicator types, and risk scores.
* Reject malformed or unsafe intelligence.
* Evaluate valid indicators against configurable risk thresholds.
* Generate `BLOCK`, `MONITOR`, or `IGNORE` decisions.
* Produce normalized firewall rule proposals.
* Keep firewall operations in **DRY-RUN** mode.
* Generate operational logs and security reports.
* Demonstrate that rejected intelligence cannot reach policy evaluation or firewall execution.

### Security Flow

```text
Threat Intelligence Feed
          |
          v
      Ingestion
          |
          v
   Record Validation
      /         \
     /           \
 VALID             INVALID
  |                  |
  v                  v
ThreatIndicator    REJECTED
  |                  |
  v                  X
Threat Policy       NO POLICY
  |                  |
  v                  X
Firewall Decision   NO FIREWALL
  |
  v
Firewall Adapter
  |
  v
DRY-RUN Execution
```

---

## 2. Security Boundary

The most important design principle in this lab is that **untrusted intelligence must never directly control firewall state**.

Only successfully validated indicators are allowed to enter policy evaluation.

Malformed indicators are recorded as rejected and are prevented from reaching:

* `ThreatPolicy.evaluate()`
* `FirewallAdapter.process()`
* Firewall rule generation
* Any host firewall command

The adversarial validation fixture deliberately contains both valid and invalid records to verify this boundary.

### Validation Result

```text
6 indicators received
├── 3 valid
│   ├── 98 → BLOCK
│   ├── 85 → MONITOR
│   └── 92 → BLOCK
│
└── 3 rejected
    ├── Invalid IP
    ├── Risk score > 100
    └── Missing/invalid risk score
```

The validation pipeline must produce:

```text
Rejected → Policy    : NONE
Rejected → Firewall  : NONE
Firewall Modification: NONE
Boundary Validation  : PASS
```

---

## 3. Policy Model

The default policy uses risk-score thresholds:

| Risk Score | Decision  | Firewall Behavior   |
| ---------: | --------- | ------------------- |
|     90–100 | `BLOCK`   | Block rule proposed |
|      70–89 | `MONITOR` | No block rule       |
|       0–69 | `IGNORE`  | No block rule       |

Default configuration:

```text
Policy Name       : default-threat-block-policy
Block Threshold   : 90
Monitor Threshold : 70
Execution Mode    : DRY-RUN
```

The thresholds are configurable through `scanner/config.py`.

---

## 4. Firewall Safety Model

This laboratory intentionally operates in **DRY-RUN** mode.

The firewall adapter creates structured execution records representing what would be proposed, but it does not change the operating system firewall.

The lab does **not** execute:

```text
iptables
nftables
firewalld
```

and does not directly modify host firewall state.

This separation allows the pipeline logic to be tested safely without introducing unintended network-policy changes.

> **Important:** Do not modify the project to execute real firewall commands unless you have explicit authorization, an approved change-management process, a controlled test environment, and an appropriate production firewall integration design.

---

## 5. Project Structure

```text
day24-threat-intel-ip-blocking/
├── authorized-target-guide.md
├── input/
│   ├── mock-threat-feed.json
│   └── validation-threat-feed.json
├── output/
│   ├── logs/
│   │   ├── day24_threat_intel.log
│   │   └── day24_validation.log
│   └── reports/
│       ├── day24_threat_intel.json
│       └── day24_threat_intel.txt
├── report/
│   ├── day24-report.md
│   └── day24-validation-report.md
├── scanner/
│   ├── config.py
│   ├── firewall.py
│   ├── ingestion.py
│   ├── models.py
│   ├── policies.py
│   ├── reporting.py
│   └── validation.py
├── tests/
│   ├── test_config.py
│   ├── test_firewall.py
│   ├── test_ingestion.py
│   ├── test_models.py
│   ├── test_policies.py
│   ├── test_reporting.py
│   ├── test_validation.py
│   └── test_validation_pipeline.py
├── README.md
└── requirements.txt
```

Python cache directories such as `__pycache__/` are intentionally omitted from the documented project structure.

---

## 6. Requirements

### Operating System

Recommended:

* Linux
* Parrot OS
* Kali Linux
* Ubuntu/Debian-based distributions

The lab can also be adapted for other platforms that support Python 3.

### Python

Recommended:

```text
Python 3.13+
```

The project was developed and tested with Python 3.13.

Verify your installation:

```bash
python3 --version
```

### Python Dependencies

Install the project requirements with:

```bash
python3 -m pip install -r requirements.txt
```

The project is intentionally lightweight and uses Python's standard library for its core pipeline functionality.

### Recommended Development Tools

For development and validation, the following are recommended:

* `git`
* Python virtual environments
* `pytest`
* A Linux terminal
* A code editor such as VS Code, Vim, or Neovim

---

## 7. Download the Project from GitHub

The recommended way to obtain the complete lab is to clone the repository.

### Clone the Repository

```bash
git clone https://github.com/Luffy-Sensei/cyber-internship.git
```

Then enter the repository:

```bash
cd cyber-internship-FINAL
```

Navigate to Day 24:

```bash
cd day24-threat-intel-ip-blocking
```

> Replace `<YOUR-GITHUB-USERNAME>` with the GitHub account or organization that hosts the repository.

### Download a ZIP Archive

Alternatively, open the repository on GitHub, select:

```text
Code → Download ZIP
```

Extract the archive and enter:

```bash
cd cyber-internship-FINAL/day24-threat-intel-ip-blocking
```

For reproducible development, cloning with Git is recommended because it preserves repository history and allows future updates.

---

## 8. Recommended Virtual Environment

Create an isolated Python environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Upgrade packaging tools:

```bash
python3 -m pip install --upgrade pip
```

Install requirements:

```bash
python3 -m pip install -r requirements.txt
```

Verify the environment:

```bash
python3 --version
python3 -m pytest --version
```

---

## 9. Running the Standard Threat-Intelligence Pipeline

The standard controlled feed is:

```text
input/mock-threat-feed.json
```

Run the pipeline with:

```bash
python3 -m scanner.reporting
```

The pipeline processes the controlled threat feed and produces:

* Threat-intelligence execution output.
* JSON report.
* Text report.
* Operational log.

Generated artifacts are stored under:

```text
output/reports/
output/logs/
```

---

## 10. Running Adversarial Validation

The adversarial validation fixture is:

```text
input/validation-threat-feed.json
```

It intentionally contains both valid and malformed threat-intelligence records.

Run:

```bash
python3 -m scanner.validation_pipeline
```

The execution demonstrates:

```text
Valid intelligence
       |
       v
Policy evaluation
       |
       v
Firewall DRY-RUN

Malformed intelligence
       |
       v
Rejected
       |
       v
NO FIREWALL ACTION
```

A successful execution ends with:

```text
Rejected → Policy    : NONE
Rejected → Firewall  : NONE
Firewall Modification: NONE
Boundary Validation  : PASS
```

The validation log is written to:

```text
output/logs/day24_validation.log
```

---

## 11. Running the Test Suite

Run the complete test suite:

```bash
python3 -m pytest -q
```

The current Day 24 implementation contains:

```text
58 tests
```

All tests should pass before the project is considered validated.

Run only the validation tests:

```bash
python3 -m pytest -q tests/test_validation.py
```

Run the pipeline security-boundary tests:

```bash
python3 -m pytest -q tests/test_validation_pipeline.py
```

A successful validation run should report:

```text
7 passed
```

for the validation unit tests and:

```text
3 passed
```

for the validation pipeline tests.

---

## 12. Output and Evidence

### Logs

Operational logs are stored in:

```text
output/logs/
```

Examples:

```text
day24_threat_intel.log
day24_validation.log
```

The validation log records:

* Accepted indicators.
* Risk scores.
* Policy decisions.
* Firewall execution status.
* Rejected indicators.
* Rejection reasons.
* Security-boundary validation status.

### Reports

Reports are stored in:

```text
output/reports/
```

The project generates both machine-readable and human-readable output:

```text
day24_threat_intel.json
day24_threat_intel.txt
```

JSON is intended for programmatic processing and future automation.

TXT output provides an operator-friendly summary.

### Documentation

Detailed reports are stored in:

```text
report/
```

including:

```text
day24-report.md
day24-validation-report.md
```

---

## 13. Threat Intelligence Data Model

Each accepted indicator contains:

```text
ip
indicator
risk_score
source
```

Example:

```json
{
  "ip": "103.45.67.89",
  "indicator": "malware_c2",
  "risk_score": 98
}
```

The ingestion and validation layers enforce constraints such as:

* IP must be valid IPv4.
* Indicator must be present.
* Risk score must be an integer.
* Risk score must be between 0 and 100.
* Feed source must be present.
* Feed ID must be present.

---

## 14. Validation Strategy

The project uses two complementary validation approaches.

### Strict Feed Ingestion

`ThreatFeedIngestor` provides strict parsing for normal pipeline ingestion.

A malformed feed fails validation rather than silently accepting invalid data.

### Record-Level Adversarial Validation

`ValidationEngine` evaluates each record independently.

This allows the security pipeline to demonstrate that:

```text
Valid record → accepted
Invalid record → rejected
```

without allowing malformed records to contaminate the valid processing path.

This separation is particularly useful when testing external or semi-trusted threat-intelligence feeds.

---

## 15. Testing the Security Boundary

The pipeline contains dedicated tests verifying that rejected indicators never appear in policy decisions or firewall execution records.

The critical invariant is:

```text
Rejected IPs ∩ Policy Decision IPs = ∅

Rejected IPs ∩ Firewall Execution IPs = ∅
```

This prevents malformed intelligence from bypassing the validation boundary.

The tests also verify that firewall execution remains:

```text
DRY-RUN
```

and that only high-risk valid indicators generate proposed block rules.

---

## 16. Operational Recommendations

For a real-world defensive deployment, this laboratory should be extended rather than connected directly to production firewall state.

Recommended controls include:

### Threat Feed Authentication

Use authenticated feeds and verify:

* TLS certificates.
* API credentials.
* Feed signatures where supported.
* Source identity.
* Feed freshness.

### Feed Integrity

Implement:

* Schema validation.
* Duplicate detection.
* Indicator expiration.
* Source reputation.
* Timestamp validation.
* Feed version tracking.

### Confidence and Risk Controls

Do not rely solely on a single risk score.

Consider combining:

```text
Risk Score
+
Source Confidence
+
Indicator Age
+
Historical Reputation
+
Internal Detection Evidence
```

### Change Control

Production firewall updates should use:

* Approval workflows.
* Audit logging.
* Rollback procedures.
* Rate limits.
* Expiration times.
* Emergency disable mechanisms.
* Staged deployment.

### Allowlisting

Maintain controlled allowlists for:

* Internal infrastructure.
* Trusted partners.
* Critical services.
* Security monitoring systems.

An external threat feed should never blindly override an approved allowlist.

### Monitoring

Monitor:

* Number of indicators received.
* Number accepted.
* Number rejected.
* Number of proposed blocks.
* Number of actual blocks.
* Feed failures.
* Validation failures.
* Unexpected changes in feed volume.

---

## 17. Production Architecture Recommendation

A production implementation should introduce additional controls between intelligence ingestion and firewall enforcement:

```text
External Threat Intelligence
            |
            v
      Secure Collector
            |
            v
    Authentication/Integrity
            |
            v
       Schema Validation
            |
            v
   Deduplication + Enrichment
            |
            v
      Risk Evaluation
            |
            v
       Policy Engine
            |
            v
       Approval Layer
            |
            v
   Firewall/API Adapter
            |
            v
     Controlled Deployment
            |
            v
     Monitoring + Audit
```

The Day 24 laboratory intentionally stops at the controlled DRY-RUN boundary.

---

## 18. Limitations

This project is an educational and defensive automation laboratory.

It does not provide:

* A production threat-intelligence feed.
* A production firewall integration.
* Guaranteed threat attribution.
* Real-time global threat intelligence.
* Automatic production blocking.
* A replacement for enterprise security controls.

The supplied IP addresses and threat labels are controlled laboratory fixtures.

---

## 19. Responsible Use

Use this project only in systems and environments where you have explicit authorization to perform security testing and defensive automation.

Do not connect the laboratory directly to a production firewall without:

1. Authorization.
2. Change approval.
3. Testing in an isolated environment.
4. Appropriate rollback procedures.
5. Security review.
6. Monitoring and audit controls.

The default project behavior is intentionally non-destructive.

---

## 20. Quick Start

For an experienced user:

```bash
git clone https://github.com/<YOUR-GITHUB-USERNAME>/cyber-internship-FINAL.git
cd cyber-internship-FINAL/day24-threat-intel-ip-blocking

python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install -r requirements.txt

python3 -m pytest -q

python3 -m scanner.validation_pipeline
```

Expected validation outcome:

```text
Indicators Received  : 6
Indicators Valid     : 3
Indicators Rejected  : 3

Rejected → Policy    : NONE
Rejected → Firewall  : NONE
Firewall Modification: NONE
Boundary Validation  : PASS
```

---

## 21. Project Status

**Day 24 — Completed**

Current validation status:

```text
Threat Intelligence Ingestion : PASS
Record Validation             : PASS
Risk Policy Evaluation        : PASS
Firewall Dry-Run Adapter      : PASS
Adversarial Validation        : PASS
Security Boundary             : PASS
Reporting                     : PASS
Regression Tests              : 58 passed
```

The laboratory successfully demonstrates controlled threat-intelligence ingestion and policy-driven firewall rule proposal while preventing malformed intelligence from reaching firewall execution.

---

## 22. License

Add the repository's applicable license here if the parent GitHub repository contains one.

If this project is published as part of a larger internship repository, follow the license and usage terms defined by that repository.