# Authorized Target Guide — Day 23 PostgreSQL Credential Auditor

## Purpose

This guide explains how to safely configure the Day 23 PostgreSQL Credential Auditor for an **authorized target** other than the default localhost fixture.

> **Important:** The current Day 23 implementation is a **non-authenticating audit engine**. It does not attempt PostgreSQL logins, transmit passwords, or perform remote credential attacks. It evaluates controlled credential/configuration fixtures against defined security policies.

Use this project only against systems, databases, credentials, and configuration data for which you have explicit authorization.

---

## 1. Default Target

The supplied validation fixture uses:

```text
127.0.0.1:5432
```

This represents a local PostgreSQL deployment.

The target metadata is stored in:

```text
input/credential-fixtures.json
```

Example structure:

```json
{
  "target": {
    "host": "127.0.0.1",
    "port": 5432,
    "service": "postgresql"
  },
  "credentials": [
    {
      "username": "postgres",
      "secret": "postgres"
    }
  ]
}
```

The target is treated as **metadata for the audit**. It does not cause the program to connect to that address.

---

# 2. Changing to Another Authorized Target

If an authorized PostgreSQL environment is being documented or assessed, change the target metadata in:

```text
input/credential-fixtures.json
```

For example:

```json
{
  "target": {
    "host": "db01.example.internal",
    "port": 5432,
    "service": "postgresql"
  },
  "credentials": [
    {
      "username": "postgres",
      "secret": "CONTROLLED_TEST_VALUE"
    },
    {
      "username": "app_user",
      "secret": "CONTROLLED_SAFE_VALUE"
    }
  ]
}
```

Use the real hostname/IP and port only when the target is authorized.

### Recommended target metadata

Prefer a resolvable hostname when available:

```text
db01.example.internal
```

rather than hard-coding an IP address.

This makes reports easier to understand when infrastructure changes.

---

# 3. Files That May Need Modification

For the **current non-authenticating implementation**, the primary file that needs changing is:

```text
input/credential-fixtures.json
```

### `input/credential-fixtures.json`

Change:

```json
"host": "127.0.0.1"
```

to the authorized target:

```json
"host": "authorized-db.example.internal"
```

Change the port only when the authorized PostgreSQL service uses a non-standard port:

```json
"port": 5432
```

The normal PostgreSQL port is `5432`.

---

## 4. Files That Normally Should NOT Be Changed

Changing the target does **not** require modifying the following files:

```text
scanner/models.py
scanner/auditor.py
scanner/reporting.py
scanner/policies.py
scanner/config.py
```

These components provide the audit model, policy evaluation, reporting, and configuration behavior.

The validation framework already loads target metadata from the fixture.

---

## 5. Validation Module

The default fixture path is defined in:

```text
scanner/validation.py
```

Currently:

```python
DEFAULT_FIXTURE = Path("input/credential-fixtures.json")
```

There is also a command-line option:

```bash
python3 -m scanner.validation --input path/to/fixture.json
```

Therefore, it is generally **better to create a separate authorized fixture** rather than modifying the default fixture.

For example:

```text
input/
├── credential-fixtures.json
└── authorized-db01-fixtures.json
```

Then run:

```bash
python3 -m scanner.validation --input input/authorized-db01-fixtures.json
```

This preserves the original reproducible laboratory dataset.

---

# 6. Never Put Real Production Passwords in Fixtures

The current tool is intentionally designed around controlled credential fixtures.

Do **not** place real production passwords into:

```text
input/
output/
screenshots/
reports/
Git history
```

Even though the reporting layer redacts secrets, the original fixture itself contains the supplied values.

A safer professional workflow is:

```text
Authorized test data
        │
        ▼
Controlled fixture
        │
        ▼
Credential Auditor
        │
        ├── Findings
        ├── Redacted evidence
        └── Reports
```

For production assessments, use synthetic or deliberately provisioned test credentials whenever possible.

---

# 7. Recommended `.gitignore` Protection

If the project is used with real assessment data, ensure sensitive local files cannot accidentally be committed.

Recommended patterns include:

```gitignore
# Local assessment data
*.secret
*.secrets
*.password
*.credentials

# Local/private fixtures
input/private/
input/local/

# Generated evidence
output/

# Python cache
__pycache__/
.pytest_cache/
*.pyc

# Virtual environment
.venv/
```

However, only ignore generated evidence if the project's evidence files are intentionally excluded from version control.

For the internship repository, keep the documented synthetic evidence that is deliberately part of the lab deliverable.

---

# 8. Running the Audit

After creating or modifying an authorized fixture:

```bash
source .venv/bin/activate
```

Run the test suite:

```bash
python3 -m pytest -q
```

Verify formatting:

```bash
git diff --check
```

Run the validation:

```bash
python3 -m scanner.validation --input input/authorized-db01-fixtures.json
```

Expected evidence includes:

```text
DAY 23 - POSTGRES CREDENTIAL AUDIT VALIDATION

Target       : authorized-db.example.internal:5432
Credentials  : ...
Findings     : ...
Status       : ...

EVIDENCE
------------------------------------------------------------
JSON       : output/reports/day23_credential_audit.json
TXT        : output/reports/day23_credential_audit.txt
LOG        : output/logs/day23_credential_audit.log

Validation : VALIDATED
```

---

# 9. Important Architectural Boundary

The current implementation deliberately follows this architecture:

```text
Credential Fixture
       │
       ▼
CredentialAuditor
       │
       ▼
CredentialPolicy
       │
       ▼
Structured Findings
       │
       ├──────────────┐
       ▼              ▼
      JSON            TXT
       │              │
       └──────┬───────┘
              ▼
             LOG
```

There is intentionally **no authentication layer**.

The auditor therefore does not:

* connect to PostgreSQL;
* submit usernames/passwords;
* brute-force credentials;
* enumerate remote database accounts;
* bypass authentication;
* attempt password spraying.

This design makes the laboratory deterministic and prevents the validation process from becoming an uncontrolled authentication-testing tool.

---

# 10. Professional-Level Improvements

For a higher-quality production or enterprise version, the following improvements are recommended.

## 10.1 Separate Target Metadata from Credential Data

Instead of storing everything in one fixture, use separate structures:

```text
input/
├── targets/
│   └── db01.json
└── credential-fixtures/
    └── db01-controlled.json
```

This creates a cleaner separation between:

```text
WHERE
```

and:

```text
WHAT IS BEING EVALUATED
```

---

## 10.2 Add Explicit Authorization Metadata

A professional assessment record should contain authorization information such as:

```json
{
  "target": {
    "host": "db01.example.internal",
    "port": 5432,
    "service": "postgresql"
  },
  "authorization": {
    "authorized": true,
    "scope": "internal security assessment",
    "owner": "Example Organization",
    "ticket": "SEC-2026-0042"
  }
}
```

The tool should refuse execution when an authorization flag is absent or invalid.

This creates an additional safety boundary between laboratory execution and real assessment data.

---

## 10.3 Add Scope Validation

A professional implementation could validate:

```text
target hostname
target IP
port
assessment scope
authorization status
environment
```

before processing an assessment.

For example:

```text
AUTHORIZED
    │
    ├── Target in scope
    ├── Service approved
    ├── Port approved
    └── Assessment window valid
             │
             ▼
          Proceed
```

Anything outside the declared scope should produce:

```text
SCOPE_DENIED
```

rather than continuing.

---

## 10.4 Use Stronger Secret Handling

The current implementation correctly prevents raw secrets from appearing in `repr()` and reports.

For a professional implementation, consider:

* avoiding unnecessary storage of plaintext secrets;
* using dedicated secret-provider interfaces;
* preventing secrets from entering logs;
* preventing secrets from entering exception messages;
* disabling secret values in debug output;
* applying explicit redaction functions to every serialized object.

The principle should be:

```text
Secret
  │
  ├── Never log
  ├── Never print
  ├── Never serialize raw
  └── Never commit
```

---

# 11. Expand the Credential Policy

The current policy detects conditions such as:

```text
postgres / postgres
postgres / <blank>
admin / admin
```

A higher-level policy engine could support configurable rules for:

* default PostgreSQL administrative credentials;
* blank passwords;
* predictable username/password combinations;
* prohibited administrative accounts;
* application use of superuser accounts;
* excessive role privileges;
* inactive accounts;
* expired credentials;
* password-authentication policy;
* role membership;
* connection limits.

Policies should remain configurable rather than hard-coded.

---

# 12. Add Configuration Profiles

A professional implementation could provide profiles such as:

```text
default
strict
enterprise
compliance
```

For example:

```text
default
  └── detects known dangerous credential patterns

strict
  └── default patterns
  └── privileged application roles
  └── weak configuration indicators

enterprise
  └── strict
  └── authorization requirements
  └── scope validation
  └── enhanced reporting
```

This makes the auditor adaptable to different environments.

---

# 13. Improve Reporting

The existing JSON/TXT reporting should remain the canonical evidence format.

A professional report can additionally include:

```text
audit_id
timestamp
target
service
assessment_scope
authorization_status
policy
accounts_evaluated
findings
severity_summary
validation_status
tool_version
```

Example:

```json
{
  "audit_id": "generated-identifier",
  "target": {
    "host": "db01.example.internal",
    "port": 5432,
    "service": "postgresql"
  },
  "accounts_evaluated": 5,
  "severity_summary": {
    "CRITICAL": 2,
    "HIGH": 1,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 0
  },
  "validation_status": "VALIDATED"
}
```

No raw credential secrets should appear.

---

# 14. Add Report Integrity

For enterprise-grade evidence handling, consider adding:

```text
SHA-256 report hash
```

and optionally:

```text
previous report reference
tool version
policy version
fixture version
```

This makes evidence easier to verify after an assessment.

---

# 15. If Real PostgreSQL Integration Is Added Later

If the project is eventually extended to inspect a real authorized PostgreSQL instance, do **not** simply add connection attempts to `auditor.py`.

Instead, create a separate controlled integration layer:

```text
scanner/
├── models.py
├── config.py
├── policies.py
├── auditor.py
├── reporting.py
├── validation.py
└── integrations/
    └── postgres.py
```

The architecture should become:

```text
Authorization / Scope Check
            │
            ▼
      PostgreSQL Adapter
            │
            ▼
       Read-only Audit
            │
            ▼
     Normalized Findings
            │
            ▼
       Policy Engine
            │
            ▼
          Reports
```

The PostgreSQL adapter should use **read-only, explicitly authorized inspection** rather than credential spraying or brute-force authentication.

---

# 16. Recommended Professional Workflow

For an authorized environment:

```text
1. Obtain explicit authorization
            │
            ▼
2. Define assessment scope
            │
            ▼
3. Create controlled fixture
            │
            ▼
4. Verify target metadata
            │
            ▼
5. Run pytest
            │
            ▼
6. Run validation
            │
            ▼
7. Inspect JSON/TXT/LOG
            │
            ▼
8. Review findings
            │
            ▼
9. Remove or securely store sensitive local data
            │
            ▼
10. Preserve sanitized evidence
```

---

# 17. Current Recommended Command Set

From the Day 23 directory:

```bash
cd ~/cyber-internship/cyber-internship-FINAL/day23-postgres-credential-auditor
```

Activate the environment:

```bash
source .venv/bin/activate
```

Run tests:

```bash
python3 -m pytest -q
```

Check whitespace:

```bash
git diff --check
```

Run the default controlled validation:

```bash
python3 -m scanner.validation
```

Run an alternate authorized fixture:

```bash
python3 -m scanner.validation --input input/authorized-db01-fixtures.json
```

Inspect generated evidence:

```bash
cat output/logs/day23_credential_audit.log
cat output/reports/day23_credential_audit.json
cat output/reports/day23_credential_audit.txt
```

---

# 18. Final Safety Recommendation

**Do not change the current architecture merely to make the tool connect to remote PostgreSQL servers.**

The current design is stronger as a professional training and validation tool because it clearly separates:

```text
Credential Analysis
        ≠
Credential Authentication
```

For higher-level deployments, introduce a separately controlled PostgreSQL integration module with:

* explicit authorization;
* scope validation;
* read-only inspection;
* strict secret handling;
* structured audit logging;
* deterministic reporting;
* failure-safe behavior;
* complete evidence preservation.

The recommended production architecture is therefore:

```text
                 Authorization
                       │
                       ▼
                Scope Validation
                       │
                       ▼
             Authorized PostgreSQL
                    Inspection
                       │
                       ▼
                Policy Engine
                       │
              ┌────────┴────────┐
              ▼                 ▼
          Findings           Passes
              │                 │
              └────────┬────────┘
                       ▼
                 Reporting
                       │
             ┌─────────┼─────────┐
             ▼         ▼         ▼
            JSON      TXT       LOG
                       │
                       ▼
              Sanitized Evidence
```

**Bottom line:** for the current Day 23 lab, changing `input/credential-fixtures.json` is sufficient to represent another authorized target. Keep the auditor non-authenticating. For a professional/enterprise version, add authorization, scope enforcement, stronger secret isolation, configurable policies, read-only PostgreSQL inspection, and evidence-integrity controls.