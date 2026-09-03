# Authorized Target Guide — Day 25 File Upload Validator

## Purpose

This guide explains how to safely adapt the Day 25 File Upload Vulnerability & Magic Bytes Validator when testing against an **authorized environment other than the default local laboratory input directory**.

Day 25 is primarily a **file-validation laboratory**, not a network scanner. Unlike network-oriented internship labs, the validator does not require an IP address, hostname, TCP port, or remote network target.

The primary target is the **authorized file/input source** being evaluated.

> **Authorization Requirement:** Only test files, upload workflows, directories, applications, and systems for which you have explicit permission to perform security testing.

---

# 1. Default Laboratory Target

The default configuration operates entirely within the Day 25 project directory:

```text
day25-file-upload-validator/
└── input/
    ├── benign/
    └── malicious/
```

The default CLI command is:

```bash
python3 -m scanner.cli
```

By default, it processes:

```text
input/
```

and generates:

```text
output/logs/upload-audit.jsonl
output/reports/day25-report.json
output/reports/day25-report.txt
```

No external network target is required.

---

# 2. What Counts as an Authorized Target?

An authorized target may be:

### Local test directory

```text
/path/to/authorized/uploads/
```

### Application staging directory

```text
/opt/authorized-app/test-uploads/
```

### Mounted test volume

```text
/mnt/authorized-upload-test/
```

### CI/CD test fixture directory

```text
/workspace/upload-fixtures/
```

### An application upload directory

Only when you have explicit authorization to test that application's upload functionality.

The validator should **not** be pointed at arbitrary system directories.

Do not use:

```text
/
 /etc
/home/<other-user>
/var/lib
/system directories
```

unless that location is explicitly part of an authorized security-testing scope.

---

# 3. Important Difference from Network-Based Labs

Day 25 does not currently perform network communication.

There is therefore no equivalent of:

```text
TARGET_IP
TARGET_HOST
TARGET_PORT
```

Instead, the relevant input is:

```text
INPUT_DIRECTORY
```

The current CLI exposes this through:

```bash
python3 -m scanner.cli --input-dir <AUTHORIZED_DIRECTORY>
```

For example:

```bash
python3 -m scanner.cli \
    --input-dir /path/to/authorized/upload-fixtures
```

The output locations can also be changed:

```bash
python3 -m scanner.cli \
    --input-dir /path/to/authorized/upload-fixtures \
    --log /path/to/audit/upload-audit.jsonl \
    --report-dir /path/to/reports
```

---

# 4. Files That Usually Do NOT Need to Change

When moving the validator to another authorized test directory, the following components generally remain unchanged:

```text
scanner/models.py
scanner/signatures.py
scanner/validator.py
scanner/storage.py
scanner/logging.py
scanner/reporting.py
scanner/pipeline.py
scanner/cli.py
```

These modules implement the security logic rather than identifying a specific environment.

This separation is intentional.

The validation engine should remain reusable while the test environment changes independently.

---

# 5. File That Controls the Input Location

The main runtime control is:

```text
scanner/cli.py
```

The CLI currently provides:

```text
--input-dir
```

Therefore, for most authorized testing scenarios, **do not modify the Python source code at all**.

Use:

```bash
python3 -m scanner.cli --input-dir /authorized/path
```

This is preferable to hard-coding an environment-specific directory into the application.

---

# 6. Configuration Changes

The security policy is defined in:

```text
scanner/config.py
```

The current default policy includes:

```text
Allowed types:
    PNG
    JPEG

Allowed extensions:
    .png
    .jpg
    .jpeg

Maximum size:
    5 MiB

Extension matching:
    Required

Server-generated filename:
    Enabled

Original filename preservation:
    Disabled

Direct execution:
    Disabled

Storage class:
    NON_EXECUTABLE_UPLOAD_STORAGE
```

These settings should normally remain unchanged when moving between authorized environments.

Only change them when the **business requirement** requires a different upload policy.

For example, if an authorized application legitimately supports PDF uploads, the policy should be extended deliberately rather than simply accepting arbitrary file types.

---

# 7. If the Authorized Application Supports Additional File Types

This implementation currently focuses on:

```text
PNG
JPEG
```

If a legitimate application requires another format, several components must be updated together.

At minimum:

```text
scanner/models.py
scanner/config.py
scanner/signatures.py
tests/
```

The new file type should receive:

1. A `FileType` enum value.
2. An approved magic-byte signature.
3. An approved extension mapping.
4. Tests for valid files.
5. Tests for signature/extension mismatch.
6. Tests for malformed or unsupported files.
7. Appropriate structural validation if the format is complex.

Do **not** simply add an extension to the allowlist without implementing content validation for that type.

---

# 8. Test Fixtures for a New Authorized Target

When testing another authorized environment, create a dedicated fixture directory.

Example:

```text
authorized-upload-test/
├── benign/
│   ├── valid.jpg
│   └── valid.png
└── invalid/
    ├── fake.jpg
    ├── fake.png
    └── unknown.txt
```

Run:

```bash
python3 -m scanner.cli \
    --input-dir authorized-upload-test
```

This keeps production data separated from controlled security-test data.

---

# 9. Do Not Replace Laboratory Fixtures with Real Malware

The Day 25 repository intentionally uses harmless mock files.

Do not replace:

```text
input/malicious/
```

with live malware.

The purpose of the laboratory is to validate the security boundary, not to execute malicious software.

For professional security testing, use approved security-test artifacts and follow the organization's rules of engagement.

---

# 10. If Testing an Actual Web Application

There is an important architectural distinction.

The current Day 25 tool validates files that are already available to the local filesystem.

It does **not** currently implement:

```text
HTTP upload
multipart/form-data
authentication
session handling
CSRF handling
remote file transfer
```

Therefore, if the authorized target is a web application, do not assume that:

```bash
python3 -m scanner.cli --input-dir <web-url>
```

will work.

It expects a filesystem directory, not:

```text
https://example.test/upload
```

A professional integration would require a separate upload-client/integration layer that receives authorized test files and passes them into the same validation pipeline.

The core validator should remain independent from that transport layer.

---

# 11. Recommended Architecture for Professional Integration

For a production-grade implementation, separate the system into:

```text
HTTP/API Layer
      |
      v
Upload Intake
      |
      v
Filename / Metadata Validation
      |
      v
Size Validation
      |
      v
Magic-Byte Validation
      |
      v
Structural Validation
      |
      v
Security Scanning
      |
      v
Safe Storage
      |
      v
Audit Logging
```

The current Day 25 implementation represents the central validation/storage-control portion of this architecture.

---

# 12. Recommended Code Improvements — Professional Level

The current implementation is intentionally focused and educational.

For a higher-quality production implementation, consider the following improvements.

## 12.1 Add MIME-Type Detection

Do not trust the client-supplied `Content-Type` header as the security authority.

Instead, compare independently determined content information against the security policy.

The client-provided MIME type may still be recorded as metadata, but it should not be treated as proof of file type.

---

## 12.2 Add Structural File Validation

Magic bytes only validate the beginning of a file.

A stronger implementation should parse supported formats using trusted libraries.

For images:

```text
Signature validation
        +
Image parser
        +
Decode verification
        +
Optional normalization/re-encoding
```

This is particularly important because valid signatures do not guarantee that the remainder of a file is valid or harmless. OWASP explicitly recommends treating signature validation as one layer rather than the sole protection.

---

## 12.3 Add Filename Normalization

Even though the current implementation generates server-side storage names, a professional intake layer should still validate the original filename.

Consider enforcing:

* Maximum filename length
* Allowed character set
* No path separators
* No control characters
* No hidden-file tricks where inappropriate
* No directory traversal sequences
* No ambiguous multi-extension handling

OWASP recommends generating application-controlled filenames and restricting unsafe filename characteristics.

---

## 12.4 Store Files Outside the Web Root

The production storage location should ideally be:

```text
Application
    |
    +----> Validation
              |
              +----> Non-executable storage
```

rather than:

```text
Web Root
    |
    +----> Uploaded User File
```

OWASP recommends storing uploaded files on a separate host where practical, or outside the web root when that is not possible.

---

## 12.5 Disable Execution

The upload storage location should not permit uploaded files to execute as application code.

For example, a web server should not interpret an uploaded object as:

```text
PHP
JSP
ASP.NET
CGI
Shell
```

even if a validation failure occurs elsewhere.

Defense should exist at both the application and infrastructure layers.

---

## 12.6 Add Antivirus or Sandbox Scanning

For higher-risk production environments:

```text
Validation
    |
    v
AV / Malware Scanner
    |
    v
Optional Sandbox
    |
    v
Safe Storage
```

OWASP recommends antivirus/sandbox analysis where available as an additional layer.

---

## 12.7 Add Content Disarm and Reconstruction

For appropriate document formats, consider CDR:

```text
Upload
  |
  v
Validate
  |
  v
CDR
  |
  v
Sanitized Document
```

This is especially relevant to environments accepting complex office/document formats.

---

## 12.8 Add Cryptographic Hashing

A professional audit record can include:

```text
SHA-256
```

for the uploaded object.

Example:

```text
sha256 = <calculated-hash>
```

This allows security teams to correlate the same file across logs and investigations without storing the file contents inside the audit record.

The hash should be calculated from the actual uploaded bytes and should not replace content validation.

---

## 12.9 Add Quarantine Storage

For higher-risk environments, consider:

```text
Incoming File
      |
      v
QUARANTINE
      |
      v
Validation
      |
      v
Security Scanning
      |
   +--+--+
   |     |
 SAFE  REJECT
   |     |
   v     v
Storage  Delete/Retain
```

This creates a stronger separation between untrusted input and trusted application storage.

---

## 12.10 Add Resource and Processing Limits

File-size limits should not be the only resource control.

Consider:

* Request-size limits
* Upload rate limits
* Concurrent-upload limits
* Image decompression limits
* Processing timeouts
* Memory limits
* Archive extraction limits
* Maximum archive nesting depth

This becomes particularly important when the application performs expensive parsing or decompression.

---

## 12.11 Improve Pipeline Type Safety

The current pipeline can be made more maintainable by using explicit return types.

For example:

```python
def _load_events(self) -> list[ValidationEvent]:
    ...
```

and importing `ValidationEvent` at module level instead of importing it inside the function.

This is a code-quality improvement rather than a security requirement.

---

## 12.12 Add CLI-Level Tests

The current test suite validates the underlying components and security boundary.

For professional CI/CD quality, add tests covering:

```text
CLI argument parsing
custom input directory
custom log path
custom report directory
empty input directory
missing input directory
permission errors
report generation
```

This ensures the operational interface receives the same level of validation as the security engine.

---

## 12.13 Add CI Security Checks

A professional repository can run automatically:

```text
pytest
ruff
mypy
bandit
pip-audit
```

depending on project requirements.

Example CI pipeline:

```text
Commit
  |
  v
Unit Tests
  |
  v
Security Tests
  |
  v
Lint
  |
  v
Type Checking
  |
  v
Dependency Audit
  |
  v
Build / Release
```

---

# 13. Recommended Configuration Model

For professional deployment, environment-specific settings should not be hard-coded.

A stronger configuration model could be:

```text
Configuration
     |
     +-- Development
     |
     +-- Test
     |
     +-- Staging
     |
     +-- Production
```

The security policy should remain explicit while paths and operational settings are environment-specific.

For example:

```text
UPLOAD_INPUT_DIR
UPLOAD_LOG_PATH
UPLOAD_REPORT_DIR
MAX_UPLOAD_SIZE
ALLOWED_FILE_TYPES
STORAGE_ROOT
```

These values can be supplied through a controlled configuration system or environment variables.

Do not put secrets into source-controlled configuration files.

---

# 14. Authorized Target Change Checklist

Before pointing the validator at another environment, confirm:

```text
[ ] Written authorization exists
[ ] Target directory is within the approved scope
[ ] Test files are approved
[ ] Production data is not unintentionally included
[ ] Input directory is correct
[ ] Output directory is isolated
[ ] File types are explicitly defined
[ ] Maximum size is appropriate
[ ] Storage is non-executable
[ ] Logs do not contain sensitive file contents
[ ] Testing window is approved
[ ] Results will be handled according to the engagement rules
```

---

# 15. Recommended Command for Another Authorized Directory

For a local authorized directory:

```bash
python3 -m scanner.cli \
    --input-dir /path/to/authorized/upload-fixtures
```

With isolated evidence directories:

```bash
python3 -m scanner.cli \
    --input-dir /path/to/authorized/upload-fixtures \
    --log /path/to/evidence/upload-audit.jsonl \
    --report-dir /path/to/evidence/reports
```

This approach is preferred over modifying source code simply to change the test location.

---

# 16. What Should Be Changed for a Different Environment?

| Requirement              | File/Location                      | Recommended Change                                |
| ------------------------ | ---------------------------------- | ------------------------------------------------- |
| Input directory          | CLI argument                       | Use `--input-dir`                                 |
| Audit location           | CLI argument                       | Use `--log`                                       |
| Report location          | CLI argument                       | Use `--report-dir`                                |
| Allowed extensions       | `scanner/config.py`                | Change only for legitimate requirements           |
| Allowed types            | `scanner/config.py` / `models.py`  | Extend deliberately                               |
| Magic signatures         | `scanner/signatures.py`            | Add signatures for supported formats              |
| Type-specific validation | `scanner/validator.py`             | Add appropriate structural checks                 |
| Security tests           | `tests/`                           | Add tests for every new format                    |
| Storage policy           | `scanner/config.py` / `storage.py` | Harden for deployment                             |
| Web integration          | New integration layer              | Do not couple network transport to core validator |

---

# 17. Golden Rule

**Do not modify the security engine merely because the authorized target changed.**

Prefer:

```text
Same security engine
        +
Different authorized input
        +
Different configuration
```

rather than:

```text
Different target
        +
Copied/modified security logic
```

Keeping the security logic independent makes testing, auditing, maintenance, and CI/CD substantially easier.

---

# 18. Final Recommendation

The current Day 25 implementation is suitable as a **controlled defensive laboratory and portfolio project**.

For a professional production implementation, the next engineering stage should add:

1. MIME/content-type correlation
2. Deep structural validation
3. Filename normalization
4. SHA-256 file hashing
5. Quarantine storage
6. Antivirus/sandbox integration
7. Non-executable isolated storage
8. Authentication and authorization
9. Rate and resource limits
10. CLI integration tests
11. Static analysis
12. Dependency vulnerability scanning
13. CI/CD security gates
14. Centralized security monitoring

The fundamental design principle should remain:

```text
UNTRUSTED INPUT
      |
      v
VALIDATE
      |
      v
SECURITY SCAN
      |
      v
SAFE STORAGE
      |
      v
AUDIT
```

Never reverse that order.

---

## References

The recommendations in this guide align with established secure file-upload guidance from OWASP, including extension allowlisting, signature validation, generated filenames, file-size restrictions, safe storage, authorization, filesystem permissions, and defense in depth.

For authorized web-application testing, OWASP's Web Security Testing Guide also documents common file-upload filter-evasion considerations and emphasizes that upload controls should not rely on a single validation mechanism.
