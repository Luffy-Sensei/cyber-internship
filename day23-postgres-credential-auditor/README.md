# Day 23 — PostgreSQL Credential Auditor

A professional, defensive PostgreSQL credential and configuration auditing component developed as part of the **Cyber Internship** laboratory series.

The tool evaluates **controlled credential fixtures** against configurable security policies and produces structured findings, severity classifications, redacted evidence, and audit reports.

> **Security note:** This implementation is intentionally **non-authenticating**. It does not attempt to log in to PostgreSQL, brute-force credentials, bypass authentication, or access remote database systems. Day 23 validates credential-security policy logic using authorized, controlled test data.

---

## 1. Objective

The objective of Day 23 is to identify insecure PostgreSQL credential configurations before they become an entry point for unauthorized database access.

The auditor detects policy violations such as:

* Default PostgreSQL administrative credentials
* Blank database credentials
* Predictable administrative credential combinations
* Other configurable credential-policy violations

The component provides:

```text
Controlled Credential Fixtures
            │
            ▼
      Credential Auditor
            │
            ▼
    Structured Findings
       │      │      │
       ▼      ▼      ▼
      JSON    TXT     LOG
```

---

## 2. Security Scope

Day 23 is designed for **defensive security validation**.

The default workflow analyzes credentials supplied through a controlled fixture:

```text
input/credential-fixtures.json
```

The tool does **not**:

* Perform live PostgreSQL authentication
* Attempt password guessing
* Brute-force credentials
* Scan external database infrastructure
* Bypass authentication controls
* Exploit PostgreSQL vulnerabilities
* Store raw secrets in generated reports

This makes the validation process deterministic, reproducible, and appropriate for an isolated internship laboratory.

---

## 3. Architecture

The implementation follows a layered architecture rather than a single-script design.

```text
day23-postgres-credential-auditor/
│
├── authorized-target-guide.txt
├── README.md
├── requirements.txt
│
├── input/
│   └── credential-fixtures.json
│
├── scanner/
│   ├── models.py
│   ├── config.py
│   ├── policies.py
│   ├── auditor.py
│   ├── reporting.py
│   └── validation.py
│
├── tests/
│   ├── test_models.py
│   ├── test_config.py
│   ├── test_policies.py
│   ├── test_auditor.py
│   ├── test_reporting.py
│   └── test_validation.py
│
├── output/
│   ├── logs/
│   │   └── day23_credential_audit.log
│   └── reports/
│       ├── day23_credential_audit.json
│       └── day23_credential_audit.txt
│
├── report/
│   └── day23-report.md
│
└── screenshots/
```

### Component responsibilities

| Component                     | Responsibility                                             |
| ----------------------------- | ---------------------------------------------------------- |
| `models.py`                   | Audit targets, credentials, findings, severity definitions |
| `config.py`                   | Configuration and validation rules                         |
| `policies.py`                 | Credential security policy evaluation                      |
| `auditor.py`                  | Core audit engine                                          |
| `reporting.py`                | JSON/TXT reporting and audit logging                       |
| `validation.py`               | Deterministic end-to-end execution                         |
| `tests/`                      | Automated verification                                     |
| `input/`                      | Controlled credential fixtures                             |
| `output/`                     | Generated evidence                                         |
| `report/`                     | Administrative and technical documentation                 |
| `authorized-target-guide.txt` | Authorization and target-use guidance                      |

---

## 4. Detection Model

The audit engine evaluates each credential record against the active security policy.

Example:

```text
postgres / postgres
        │
        ▼
DEFAULT_ADMIN_CREDENTIAL
        │
        ▼
     CRITICAL
```

A blank secret is treated as a separate security condition:

```text
postgres / <blank>
        │
        ▼
BLANK_CREDENTIAL
        │
        ▼
     CRITICAL
```

Predictable administrative combinations are also evaluated:

```text
admin / admin
        │
        ▼
ADMIN_DEFAULT_CREDENTIAL
        │
        ▼
       HIGH
```

A strong application credential that does not violate the configured policy produces no finding:

```text
app_user / strong-secret
        │
        ▼
NO_POLICY_VIOLATION
        │
        ▼
       PASS
```

---

## 5. Secret Handling

Credential auditing must never create a second security problem by exposing the credentials it is supposed to protect.

The implementation therefore uses redaction.

Example:

```text
Raw secret:
postgres

Evidence representation:
pos***
```

Blank credentials are represented as:

```text
<BLANK>
```

Credential objects also use a redacted representation rather than exposing their underlying secret.

Generated reports are designed to contain:

```text
user=postgres
secret=pos***
```

rather than:

```text
user=postgres
secret=postgres
```

Raw secrets should never be committed to Git, placed in screenshots, or included in reports.

---

## 6. Validation Fixture

The controlled validation dataset contains multiple credential conditions, including:

* Known PostgreSQL default credential
* Blank credential
* Administrative default
* Safe application credential
* Multiple accounts

The fixture exists only to exercise the defensive detection logic.

It should never contain real production credentials.

---

## 7. Requirements

### Operating environment

Recommended environment:

* Linux
* Python 3.11+
* Python virtual environment
* Git

The project has been developed and validated with Python 3.13.

### Python dependencies

The current implementation is intentionally lightweight and uses Python's standard library for the core auditing functionality.

Development/testing requires:

```text
pytest
```

The exact dependency declaration is maintained in:

```text
requirements.txt
```

---

## 8. Installation

Clone the Cyber Internship repository and enter the project directory.

```bash
git clone https://github.com/Luffy-Sensei/cyber-internship.git
cd cyber-internship/day23-postgres-credential-auditor
```

If the repository has already been cloned:

```bash
cd ~/cyber-internship/cyber-internship-FINAL/day23-postgres-credential-auditor
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project requirements:

```bash
python3 -m pip install -r requirements.txt
```

Run the test suite:

```bash
python3 -m pytest -q
```

---

## 9. Running the Audit

The deterministic validation runner can be executed with:

```bash
python3 -m scanner.validation
```

The default fixture is:

```text
input/credential-fixtures.json
```

A custom authorized fixture can be supplied with:

```bash
python3 -m scanner.validation --input path/to/authorized-fixture.json
```

The supplied data must follow the expected fixture structure.

---

## 10. Example Validation Output

A successful controlled validation produces evidence similar to:

```text
============================================================
DAY 23 - POSTGRES CREDENTIAL AUDIT VALIDATION
============================================================

Target       : 127.0.0.1:5432
Credentials  : 5
Findings     : 3
Status       : FINDINGS

FINDINGS
------------------------------------------------------------
CRITICAL DEFAULT_ADMIN_CREDENTIAL   user=postgres
CRITICAL BLANK_CREDENTIAL            user=postgres
HIGH     ADMIN_DEFAULT_CREDENTIAL    user=admin

SAFE CREDENTIAL CHECK
------------------------------------------------------------
app_user -> PASS

EVIDENCE
------------------------------------------------------------
JSON       : output/reports/day23_credential_audit.json
TXT        : output/reports/day23_credential_audit.txt
LOG        : output/logs/day23_credential_audit.log

Validation : VALIDATED
```

`FINDINGS` does not mean the validation itself failed.

It means the auditor successfully identified security findings in the controlled dataset.

The final:

```text
Validation : VALIDATED
```

means the expected detection behavior was successfully demonstrated.

---

## 11. Generated Evidence

The reporting layer generates three primary evidence artifacts:

```text
output/
├── logs/
│   └── day23_credential_audit.log
└── reports/
    ├── day23_credential_audit.json
    └── day23_credential_audit.txt
```

### JSON report

The JSON report provides machine-readable audit information including:

* Audit ID
* UTC timestamp
* Target metadata
* Number of accounts evaluated
* Structured findings
* Severity summary
* Active policy
* Validation status
* Redacted credential representations

Example conceptual structure:

```json
{
  "audit_id": "...",
  "timestamp": "...",
  "target": {
    "host": "127.0.0.1",
    "port": 5432,
    "service": "postgresql"
  },
  "accounts_evaluated": 5,
  "findings": [],
  "severity_summary": {},
  "policy": {},
  "validation_status": "VALIDATED"
}
```

Actual generated findings and metadata depend on the controlled fixture.

### TXT report

The TXT report provides a human-readable administrative representation suitable for:

* Internship evidence
* Manual review
* Security documentation
* Audit demonstrations

### Log

The audit log records reporting and validation events without exposing raw secrets.

---

## 12. Verification

Before considering Day 23 complete, run:

```bash
python3 -m pytest -q
```

Then:

```bash
git diff --check
```

Then execute the controlled validation:

```bash
python3 -m scanner.validation
```

Inspect the generated evidence:

```bash
cat output/logs/day23_credential_audit.log
```

```bash
cat output/reports/day23_credential_audit.json
```

```bash
cat output/reports/day23_credential_audit.txt
```

Finally:

```bash
tree -a -I '__pycache__|.pytest_cache|.venv'
```

---

## 13. Security Verification

The generated artifacts should never contain raw credential secrets.

A local verification can be performed against known fixture secrets:

```bash
grep -R "REAL_SECRET_HERE" output/
```

No matches should be present.

Instead, evidence should use representations such as:

```text
pos***
adm***
<BLANK>
```

Do not use real passwords in demonstration fixtures.

---

## 14. Administrative PostgreSQL Hardening Blueprint

### Authorization

PostgreSQL access should follow least privilege.

```text
Application
     │
     ▼
Application Role
     │
     ├── Required Database
     ├── Required Schema
     └── Required Operations
```

Applications should not use PostgreSQL superuser or administrative accounts.

Administrative roles should be reserved for controlled administrative operations.

Recommended controls include:

* Separate application and administrative roles
* Minimal database privileges
* Minimal schema privileges
* Explicit object permissions
* Controlled role membership
* Periodic privilege review
* Removal of unused accounts
* Strong authentication policies

---

### Connection Limiting

Database exposure should also consider connection consumption.

```text
Client
  │
  ▼
Network Boundary
  │
  ▼
PostgreSQL
  │
  ▼
Connection Limits / Pooling
  │
  ▼
Authenticated Role
```

Recommended controls include:

* Restrict database network exposure
* Use appropriate connection limits
* Use connection pooling where appropriate
* Monitor connection consumption
* Avoid unrestricted database access from untrusted networks
* Separate application connection pools where operationally justified

Connection limiting reduces resource exhaustion risk and helps prevent uncontrolled connection consumption.

---

### Data Protection

Sensitive PostgreSQL data should be protected through appropriate layers:

```text
Encryption in Transit
        +
Encryption at Rest
        +
Application-Level Protection
        +
Controlled Key Management
```

The appropriate mechanism depends on the sensitivity and threat model of the data.

Keys should be managed separately from the protected data and access to them should be tightly controlled.

---

## 15. PostgreSQL RLS Security Model

A critical technical distinction is made in this project:

> **Row-Level Security (RLS) is an authorization mechanism, not an encryption mechanism.**

A more accurate architecture is:

```text
Application
     │
     ▼
Authenticated DB Role
     │
     ▼
Row-Level Security
     │
     ▼
Authorized Rows
     │
     ▼
Protected Sensitive Data
```

RLS can restrict which rows a role may access.

It does not itself encrypt those rows.

Encryption and authorization should therefore be treated as separate security controls that can complement one another.

---

## 16. Recommended Enterprise Architecture

A production-oriented conceptual architecture is:

```text
                    INTERNET
                       │
                       ▼
              ┌─────────────────┐
              │ Network Boundary│
              │ / Firewall / LB │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Application     │
              │ Tier            │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Connection Pool │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ PostgreSQL      │
              │ Cluster         │
              └────────┬────────┘
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
       Authenticated       Administrative
       Application Role        Role
              │                 │
              ▼                 ▼
        Least Privilege    Controlled Access
              │
              ▼
        Row-Level Security
              │
              ▼
        Authorized Data
```

---

## 17. Authorized Target Policy

Only systems for which explicit authorization has been granted should be evaluated.

Before modifying a target or fixture, consult:

```text
authorized-target-guide.txt
```

Recommended laboratory targets include:

* `127.0.0.1`
* Local PostgreSQL test environments
* Dedicated virtual machines
* Intentionally configured training infrastructure
* Systems for which the operator has explicit authorization

Do not use this project to test credentials against systems you do not own or have permission to assess.

---

## 18. Recommendations

For real PostgreSQL deployments:

1. Never use default administrative credentials.
2. Never leave database credentials blank.
3. Never hard-code production secrets into source code.
4. Use dedicated application roles.
5. Apply least privilege.
6. Restrict PostgreSQL network exposure.
7. Use strong authentication mechanisms.
8. Apply appropriate connection limits.
9. Use connection pooling where appropriate.
10. Enable TLS for database connections where required.
11. Protect sensitive data at rest.
12. Separate encryption keys from encrypted data.
13. Use RLS where row-level authorization is required.
14. Monitor authentication and database access events.
15. Review database roles and privileges periodically.
16. Rotate credentials according to organizational policy.
17. Never place raw credentials in reports, screenshots, logs, or Git repositories.

---

## 19. Testing Coverage

The project uses automated tests across the major architectural components.

The test suite covers:

* Configuration validation
* Target validation
* Credential representation
* Secret redaction
* Severity handling
* Policy evaluation
* Default credential detection
* Blank credential detection
* Administrative credential detection
* Safe credential handling
* Audit engine behavior
* JSON reporting
* TXT reporting
* Audit metadata
* Severity summaries
* Validation status
* Output directory creation
* Logging behavior

The Day 23 implementation currently validates successfully with:

```text
31 passed
```

---

## 20. Evidence Standard

Day 23 follows the same evidence-driven methodology used throughout the internship.

```text
                 CODE
                  │
                  ▼
              UNIT TESTS
                  │
                  ▼
          CONTROLLED EXECUTION
                  │
                  ▼
        SECURITY FINDINGS
                  │
          ┌───────┼────────┐
          ▼       ▼        ▼
         JSON     TXT      LOG
          │       │        │
          └───────┼────────┘
                  ▼
          ARCHITECTURE REPORT
                  │
                  ▼
          SCREENSHOT EVIDENCE
```

The final evidence package demonstrates both:

* **Functional correctness**
* **Security-safe reporting**

Passing tests alone is not considered sufficient evidence.

---

## 21. GitHub Repository

Day 23 is maintained as part of the Cyber Internship repository:

**Repository:** `Luffy-Sensei/cyber-internship`

To obtain the project:

```bash
git clone https://github.com/Luffy-Sensei/cyber-internship.git
```

Then:

```bash
cd cyber-internship/day23-postgres-credential-auditor
```

For an existing local clone, update the repository before working:

```bash
git pull --ff-only origin main
```

Then activate the project's virtual environment and run the verification commands described above.

---

## 22. Project Status

**Day:** 23
**Project:** PostgreSQL Credential Auditor
**Focus:** Defensive credential/configuration auditing
**Authentication:** Non-authenticating / fixture-based
**Reporting:** JSON + TXT + LOG
**Secret handling:** Redacted
**Automated validation:** Passing
**Architecture:** Layered / modular
**Administrative blueprint:** Included

---

## 23. Disclaimer

This project is intended for authorized defensive security research, education, laboratory validation, and internship training.

Only evaluate systems, databases, credentials, or infrastructure for which you have explicit authorization.

The controlled Day 23 implementation deliberately avoids live credential authentication and focuses on safe policy analysis using supplied fixtures.