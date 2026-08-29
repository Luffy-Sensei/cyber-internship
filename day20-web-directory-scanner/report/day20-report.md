# Day 20 Security Assessment Report

## Web Directory Discovery & Sensitive Resource Exposure

**Assessment Type:** Controlled Web Application Security Assessment
**Assessment Phase:** Phase 5 — Real Local Lab Execution
**Target:** `http://127.0.0.1:5000`
**Environment:** Intentionally Vulnerable Local Training Laboratory
**Wordlist:** `input/paths.txt`
**Assessment Date:** 2026-08-29
**Scanner:** Day 20 Web Directory Discovery Scanner
**Authorization Scope:** Local laboratory environment only

---

## 1. Executive Summary

A controlled web directory discovery assessment was conducted against an intentionally vulnerable local HTTP application as part of the Day 20 cybersecurity internship laboratory.

The objective was to validate the complete scanner workflow from HTTP path discovery through security detection, risk classification, and report generation.

The assessment tested **11 wordlist entries** and generated **5 security findings**:

| Severity  | Count |
| --------- | ----: |
| Critical  |     2 |
| High      |     0 |
| Medium    |     2 |
| Low       |     1 |
| **Total** | **5** |

Two critical findings were confirmed:

1. `/.env` was accessible and returned HTTP `200 OK`.
2. `/backup.sql` was accessible and returned HTTP `200 OK`.

An administrative endpoint, `/admin`, returned HTTP `403 Forbidden`, demonstrating that access control was functioning for that resource.

The assessment successfully demonstrated an end-to-end security scanning and reporting workflow against a controlled local target.

---

# 2. Assessment Objective

The primary objective was to determine whether the Day 20 scanner could reliably:

* Discover HTTP-accessible paths.
* Identify endpoints returning successful responses.
* Detect sensitive resources.
* Classify HTTP response conditions.
* Assign security severity and risk scores.
* Generate actionable remediation recommendations.
* Produce machine-readable JSON output.
* Produce human-readable TXT output.
* Execute successfully through the command-line interface.
* Validate the complete pipeline against a real local HTTP service.

---

# 3. Scope

## 3.1 Target

```text
http://127.0.0.1:5000
```

The target was hosted entirely on the local system and was intentionally configured as a vulnerable training application.

## 3.2 Wordlist

```text
input/paths.txt
```

The wordlist contained 11 usable paths covering:

* Common application routes
* Administrative locations
* API paths
* Sensitive configuration files
* Database backups
* Archive files
* Operational locations

## 3.3 Authorization

Testing was restricted to the intentionally vulnerable local laboratory.

No external systems or unauthorized infrastructure were targeted during the assessment.

---

# 4. Methodology

The scanner implements the following processing pipeline:

```text
Wordlist
   ↓
HTTP Client
   ↓
PathResult
   ↓
Security Detector
   ↓
Security Finding
   ↓
Risk Analyzer
   ↓
Risk Assessment
   ↓
WebDirectoryAnalyzer
   ↓
ScanReporter
   ├──────────────┐
   ▼              ▼
 JSON             TXT
```

Each wordlist entry was requested from the target application.

The resulting HTTP response was converted into a `PathResult`, which was then evaluated by the detection engine.

Detected conditions were passed to the risk-analysis layer, where each finding received:

* Rule ID
* Severity
* Risk score
* Classification
* Recommendation

The resulting findings were then incorporated into the final assessment reports.

---

# 5. Security Detection Rules

The assessment used the following detection rules:

| Rule ID              | Condition                        | Risk Score | Severity |
| -------------------- | -------------------------------- | ---------: | -------- |
| `SENSITIVE_EXPOSURE` | Sensitive path returns HTTP 200  |         90 | CRITICAL |
| `DIRECTORY_200`      | Endpoint returns HTTP 200        |         20 | MEDIUM   |
| `DIRECTORY_5XX`      | Server returns HTTP 5xx          |         15 | MEDIUM   |
| `DIRECTORY_REDIRECT` | Endpoint redirects               |         10 | LOW      |
| `DIRECTORY_403`      | Endpoint exists but is forbidden |          5 | LOW      |

Sensitive-path detection is particularly important because an HTTP `200 OK` response from a configuration file, database backup, or other sensitive resource can represent a significant information-disclosure vulnerability.

---

# 6. Phase 5 Execution

The scanner was executed against the local vulnerable application using:

```bash
python3 -m scanner.cli \
  --url http://127.0.0.1:5000 \
  --wordlist input/paths.txt \
  --json output/reports/day20_phase5.json \
  --text output/reports/day20_phase5.txt \
  --verbose
```

The execution completed successfully.

## 6.1 Scan Metrics

```text
Target        : http://127.0.0.1:5000
Wordlist      : 11 entries
Requests      : 11
Findings      : 5
Critical      : 2
High          : 0
Medium        : 2
Low           : 1
```

The scanner completed all 11 requests without terminating prematurely.

---

# 7. Findings Summary

| Path          | HTTP Status | Rule                 | Severity | Score |
| ------------- | ----------: | -------------------- | -------- | ----: |
| `/admin`      |         403 | `DIRECTORY_403`      | LOW      |     5 |
| `/.env`       |         200 | `DIRECTORY_200`      | MEDIUM   |    20 |
| `/.env`       |         200 | `SENSITIVE_EXPOSURE` | CRITICAL |    90 |
| `/backup.sql` |         200 | `DIRECTORY_200`      | MEDIUM   |    20 |
| `/backup.sql` |         200 | `SENSITIVE_EXPOSURE` | CRITICAL |    90 |

The scanner therefore identified both the generic successful endpoint condition and the more significant sensitive-resource exposure condition for the two intentionally vulnerable files.

---

# 8. Finding D20-001 — Environment File Exposure

**Severity:** CRITICAL
**Risk Score:** 90
**Rule:** `SENSITIVE_EXPOSURE`
**Endpoint:** `/.env`
**HTTP Status:** `200 OK`

## Description

The `.env` endpoint was publicly accessible through the local web server.

The following request was used to verify the finding:

```bash
curl -i http://127.0.0.1:5000/.env
```

The server returned:

```text
HTTP/1.0 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 55
```

The response contained environment-style application configuration:

```text
APP_ENV=development
DEBUG=true
DATABASE_HOST=localhost
```

The file was intentionally exposed by the training laboratory.

## Security Impact

In a real application, publicly accessible environment files can expose sensitive configuration such as:

* Database credentials
* API keys
* Authentication secrets
* Application secret keys
* Service endpoints
* Debug configuration
* Internal infrastructure information

Exposure of such information may enable further compromise depending on the contents of the file.

## Risk Assessment

The finding was assigned:

```text
Severity      : CRITICAL
Risk Score    : 90
Classification: CRITICAL
```

The high severity is justified because configuration files can contain secrets that directly affect the confidentiality and integrity of an application environment.

## Remediation

Recommended actions:

1. Remove `.env` files from the web-accessible document root.
2. Store application configuration outside the public web directory.
3. Configure the web server to deny access to hidden configuration files.
4. Prevent sensitive files from being included in deployment artifacts.
5. Rotate any credentials or secrets that may have been exposed.
6. Add automated deployment checks for sensitive files.

---

# 9. Finding D20-002 — Database Backup Exposure

**Severity:** CRITICAL
**Risk Score:** 90
**Rule:** `SENSITIVE_EXPOSURE`
**Endpoint:** `/backup.sql`
**HTTP Status:** `200 OK`

## Description

The database backup endpoint was publicly accessible through the local HTTP service.

Verification was performed using:

```bash
curl -i http://127.0.0.1:5000/backup.sql
```

The server returned:

```text
HTTP/1.0 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 59
```

The response contained SQL backup content:

```text
-- Intentional Day 20 lab artifact
SELECT 'training-data';
```

The exposed database backup was intentionally created for this security laboratory.

## Security Impact

In a production environment, publicly accessible database backups could expose:

* Application data
* User information
* Database schema
* Credentials
* Internal records
* Sensitive business information

The severity would depend on the contents of the backup and whether it contained exploitable credentials or confidential information.

## Risk Assessment

The finding was assigned:

```text
Severity      : CRITICAL
Risk Score    : 90
Classification: CRITICAL
```

## Remediation

Recommended actions:

1. Remove database backups from the web document root.
2. Store backups in dedicated protected storage.
3. Apply restrictive filesystem permissions.
4. Prevent database and archive files from being served by the web server.
5. Review deployment packages for accidental backup files.
6. Rotate credentials if a real backup containing secrets was exposed.
7. Implement automated checks for files such as `.sql`, `.zip`, `.tar`, and similar backup artifacts.

---

# 10. Finding D20-003 — Administrative Endpoint

**Severity:** LOW
**Risk Score:** 5
**Rule:** `DIRECTORY_403`
**Endpoint:** `/admin`
**HTTP Status:** `403 Forbidden`

## Description

The `/admin` endpoint was discovered during directory enumeration but returned HTTP `403 Forbidden`.

Verification:

```bash
curl -i http://127.0.0.1:5000/admin
```

Response:

```text
HTTP/1.0 403 Forbidden
```

This indicates that the endpoint exists but access was denied.

## Security Impact

The response itself does not indicate an access-control failure.

However, administrative interfaces should remain protected because they may contain privileged functionality.

## Remediation

Recommended actions:

* Maintain the existing access-control mechanism.
* Require strong authentication for administrative functionality.
* Verify authorization controls server-side.
* Test for alternate paths that could bypass restrictions.
* Monitor administrative endpoints for unauthorized access attempts.

---

# 11. Negative Controls

Several paths returned HTTP `404 Not Found`, including:

```text
/dashboard
/api
/api/v1
/.git/
/backup.zip
/login
/uploads
/static
```

These responses did not generate security findings under the configured detection rules.

This demonstrates that the scanner distinguishes between discovered resources and paths that are not present.

---

# 12. Evidence

The assessment generated machine-readable and human-readable evidence.

## JSON Report

```text
output/reports/day20_phase5.json
```

The JSON report contains:

* Schema version
* Scan ID
* Target
* Timestamps
* Duration
* Wordlist size
* Request count
* Findings
* Severity summary

## TXT Report

```text
output/reports/day20_phase5.txt
```

The TXT report provides a human-readable representation of the scan results.

## Manual HTTP Evidence

The critical findings were independently verified with direct HTTP requests:

```bash
curl -i http://127.0.0.1:5000/.env
```

```bash
curl -i http://127.0.0.1:5000/backup.sql
```

The `/admin` access-control behavior was also verified:

```bash
curl -i http://127.0.0.1:5000/admin
```

---

# 13. Report Validation

The generated JSON report was independently loaded and inspected.

Validation confirmed:

```text
Schema: 1.0
Target: http://127.0.0.1:5000
Requests: 11
Findings: 5
Critical: 2
```

The sensitive findings were confirmed as:

```text
SENSITIVE: .env | severity=CRITICAL | score=90
SENSITIVE: backup.sql | severity=CRITICAL | score=90
```

This provides evidence that the scanner's internal findings were preserved correctly through the final JSON reporting stage.

---

# 14. Automated Test Validation

The complete project test suite was executed using:

```bash
python3 -m pytest -q
```

Final result:

```text
42 passed
```

The test suite covers:

* Configuration
* Wordlist parsing
* HTTP client behavior
* Security detection
* Sensitive-path rules
* Risk analysis
* Analyzer behavior
* Reporting
* Report schema validation
* CLI integration
* End-to-end processing

The successful test suite provides regression coverage for the scanner's core functionality.

---

# 15. Remediation Priority

The recommended remediation order is:

## Priority 1 — Remove Sensitive Files

Immediately remove environment files and database backups from any production web root.

Affected laboratory paths:

```text
/.env
/backup.sql
```

## Priority 2 — Enforce Web-Server Restrictions

Configure the application/web server so that sensitive configuration, backup, and archive files cannot be requested directly.

## Priority 3 — Protect Administrative Interfaces

Maintain authentication and authorization controls around administrative endpoints such as:

```text
/admin
```

## Priority 4 — Add Deployment Controls

Implement automated checks that prevent sensitive artifacts from entering production web directories.

Potential checks should include:

```text
.env
*.sql
*.zip
*.tar
*.tar.gz
backup*
```

and other project-specific sensitive files.

---

# 16. Security Recommendations

The following controls are recommended for production environments:

### Secure Deployment

Keep configuration, secrets, source code, and backups outside web-accessible directories.

### Least Privilege

Apply restrictive filesystem permissions to sensitive resources.

### Web-Server Deny Rules

Explicitly deny direct access to sensitive file types and hidden configuration files.

### Secret Management

Use a dedicated secret-management mechanism rather than storing credentials in publicly accessible files.

### Automated Security Checks

Integrate sensitive-file detection into CI/CD pipelines.

### Backup Security

Store database backups in protected storage that is not directly exposed through HTTP.

### Continuous Monitoring

Monitor web-server logs for repeated requests to sensitive paths.

---

# 17. Limitations

This assessment was intentionally limited to a controlled local training environment.

The scanner does not attempt to:

* Exploit discovered vulnerabilities.
* Authenticate to protected applications.
* Perform brute-force attacks.
* Crawl links dynamically.
* Analyze application source code.
* Determine the contents of arbitrary production resources.
* Assess external infrastructure.
* Perform destructive testing.

The results therefore represent the behavior of the configured scanner and laboratory rather than a complete penetration test.

---

# 18. Conclusion

The Day 20 Web Directory Discovery Scanner successfully completed an end-to-end security assessment against the intentionally vulnerable local HTTP laboratory.

The assessment demonstrated that the scanner can:

* Process a web path wordlist.
* Send HTTP requests to a controlled target.
* Record HTTP response information.
* Detect accessible endpoints.
* Identify sensitive resources.
* Generate security findings.
* Assign risk scores and severity classifications.
* Produce remediation recommendations.
* Generate validated JSON reports.
* Generate human-readable TXT reports.
* Execute through the CLI.
* Integrate multiple scanner components into a single workflow.

The Phase 5 execution produced the expected laboratory findings:

```text
11 requests
5 findings
2 Critical
0 High
2 Medium
1 Low
```

The two critical exposures were:

```text
/.env        → HTTP 200 → CRITICAL → Score 90
/backup.sql  → HTTP 200 → CRITICAL → Score 90
```

The `/admin` endpoint correctly demonstrated restricted access:

```text
/admin       → HTTP 403 → LOW → Score 5
```

The project test suite completed successfully with:

```text
42 passed
```

Overall, Day 20 demonstrates a complete and reproducible workflow for **web directory discovery, sensitive-resource detection, risk assessment, evidence collection, and security reporting** within an authorized laboratory environment.

---

# 19. Assessment Status

```text
DAY 20 — WEB DIRECTORY DISCOVERY & EXPOSURE ASSESSMENT

[✓] Scanner implemented
[✓] HTTP client validated
[✓] Wordlist processing validated
[✓] Security detection validated
[✓] Sensitive-path detection validated
[✓] Risk analysis validated
[✓] JSON reporting validated
[✓] TXT reporting validated
[✓] Report schema validated
[✓] CLI integration validated
[✓] Local vulnerable laboratory validated
[✓] Phase 5 execution completed
[✓] Critical findings confirmed
[✓] Evidence generated
[✓] Remediation documented
[✓] Automated tests passing

Test Status : 42 passed
Scan Status : 11 requests / 5 findings
Assessment  : COMPLETE
```

**End of Day 20 Security Assessment Report**
