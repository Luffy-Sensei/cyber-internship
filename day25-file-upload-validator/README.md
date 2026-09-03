# Day 25 — File Upload Vulnerability & Magic Bytes Validator

A defensive Python security laboratory for validating uploaded files using **magic-byte signatures**, extension allowlisting, file-size restrictions, safe storage policies, and structured security auditing.

The project demonstrates how applications can prevent common file-upload validation bypasses where an attacker attempts to disguise an unsupported or executable file by changing its filename extension.

> **Security Notice:** This project is a controlled defensive security laboratory. All included malicious-file scenarios are harmless mock fixtures. No real malware is included, executed, or required.

---

## Overview

File-upload functionality is a common attack surface in web applications.

A weak implementation may trust the filename extension:

```text
image.jpg
    |
    v
".jpg" detected
    |
    v
ACCEPT
```

An attacker can abuse this by renaming an unsupported or executable file:

```text
script.sh
    |
    v
fake.jpg
    |
    v
extension-only validation
    |
    v
incorrectly accepted
```

This laboratory demonstrates a stronger validation workflow:

```text
                    Uploaded File
                          |
                          v
                 +----------------+
                 | Size Validation|
                 +----------------+
                          |
                          v
                 +----------------+
                 | Extension      |
                 | Allowlist      |
                 +----------------+
                          |
                          v
                 +----------------+
                 | Magic-Byte     |
                 | Detection      |
                 +----------------+
                          |
                          v
                 +----------------+
                 | Extension /    |
                 | Signature Match|
                 +----------------+
                          |
                    +-----+-----+
                    |           |
                 ACCEPT       REJECT
                    |           |
                    v           v
             Safe Storage    No Storage
                    |
                    v
            Audit + Reporting
```

The implementation supports controlled validation of:

* PNG
* JPEG

---

## Security Objectives

The project is designed to demonstrate the following defensive controls:

* Extension allowlisting
* Magic-byte validation
* Extension/signature consistency checking
* Maximum upload-size enforcement
* Server-generated storage filenames
* Disabled original filename preservation
* Non-executable upload storage
* Rejection before storage
* Structured JSONL audit logging
* JSON security reporting
* Human-readable security reporting
* Automated adversarial/security-boundary testing

---

## Features

### Magic-Byte Detection

The validator examines the beginning of the file and compares it against approved binary signatures.

Supported signatures:

| File Type | Magic Bytes               |
| --------- | ------------------------- |
| PNG       | `89 50 4E 47 0D 0A 1A 0A` |
| JPEG      | `FF D8 FF`                |

The implementation reads only the required file header for signature detection.

---

### Extension Allowlisting

The default policy permits:

```text
.png
.jpg
.jpeg
```

Unsupported extensions are rejected before the file can enter the storage workflow.

---

### Extension/Signature Consistency

The validator ensures that the detected binary type is consistent with the declared filename extension.

For example:

```text
image.png
    |
    +-- Detected signature: JPEG
    |
    +-- Result: REJECT
```

This prevents attackers from simply pairing a valid signature with an inappropriate extension.

---

### File-Size Enforcement

The default maximum upload size is:

```text
5 MiB
```

The validator compares the actual filesystem size against the upload policy before accepting the file.

---

### Safe Storage Policy

Accepted files receive a server-generated UUID-based storage name.

Example:

```text
Original filename:
profile.jpg

Storage identifier:
<server-generated-uuid>.jpg
```

The original filename is not used as the storage identifier.

The configured storage classification is:

```text
NON_EXECUTABLE_UPLOAD_STORAGE
```

Rejected files do not receive a storage filename.

---

### Structured Security Auditing

Validation decisions are written to:

```text
output/logs/upload-audit.jsonl
```

Each event records security-relevant metadata such as:

* Timestamp
* Filename
* Validation action
* Validation status
* Reason
* Detected file type
* File size
* Storage decision
* Generated storage name
* Storage classification

File contents are never written to the audit log.

---

## Project Structure

```text
day25-file-upload-validator/
│
├── input/
│   ├── benign/
│   │   ├── valid.jpg
│   │   └── valid.png
│   │
│   └── malicious/
│       ├── fake.jpg
│       ├── fake.png
│       └── unknown.txt
│
├── output/
│   ├── logs/
│   │   └── upload-audit.jsonl
│   │
│   └── reports/
│       ├── day25-report.json
│       └── day25-report.txt
│
├── report/
│   └── day25-report.md
│
├── scanner/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── logging.py
│   ├── models.py
│   ├── pipeline.py
│   ├── reporting.py
│   ├── signatures.py
│   ├── storage.py
│   └── validator.py
│
├── tests/
│   ├── test_config.py
│   ├── test_logging.py
│   ├── test_models.py
│   ├── test_pipeline.py
│   ├── test_reporting.py
│   ├── test_security_boundary.py
│   ├── test_signatures.py
│   ├── test_storage.py
│   └── test_validator.py
│
├── authorized-target-guide.md
├── README.md
└── requirements.txt
```

---

## Requirements

### Operating System

The laboratory is designed for Linux environments and has been developed and tested on Parrot OS.

It should also be suitable for other modern Linux distributions.

### Python

Recommended:

```text
Python 3.13+
```

The project was developed and tested using Python 3.13.5.

### Python Dependencies

Install the project dependencies from:

```text
requirements.txt
```

The test environment uses `pytest`.

---

## Installation

### 1. Clone the Repository

Clone the main GitHub repository:

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
```

Enter the repository:

```bash
cd cyber-internship-FINAL
```

Navigate to Day 25:

```bash
cd day25-file-upload-validator
```

> Replace `<YOUR-GITHUB-REPOSITORY-URL>` with the actual GitHub repository URL.

---

### 2. Create a Virtual Environment

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

---

### 3. Install Requirements

```bash
python3 -m pip install -r requirements.txt
```

---

## Downloading Only the Day 25 Tool

If the complete internship repository is already available locally, navigate directly to:

```bash
cd cyber-internship-FINAL/day25-file-upload-validator
```

If the repository is hosted publicly on GitHub, the complete project can be downloaded using Git:

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
```

Then:

```bash
cd cyber-internship-FINAL/day25-file-upload-validator
```

For a GitHub ZIP download, open the repository's GitHub page and use:

```text
Code → Download ZIP
```

Extract the repository and navigate to:

```text
day25-file-upload-validator/
```

---

## Usage

### Run the Complete Test Suite

From the Day 25 directory:

```bash
python3 -m pytest -q
```

The validated Day 25 implementation currently passes:

```text
58 passed
```

---

### Run Security-Boundary Tests

To specifically test adversarial upload scenarios:

```bash
python3 -m pytest -q tests/test_security_boundary.py
```

Expected result:

```text
5 passed
```

These tests verify that:

* Fake JPEG uploads are rejected
* Extension-only bypasses are rejected
* Signature/extension mismatches are rejected
* Rejected files receive no storage name
* Valid uploads receive server-generated storage names

---

### Run the Upload Validator

Execute the CLI:

```bash
python3 -m scanner.cli
```

The default input directory is:

```text
input/
```

The default audit log is:

```text
output/logs/upload-audit.jsonl
```

The default report directory is:

```text
output/reports/
```

---

## Example Runtime

A clean test execution produces results similar to:

```text
============================================================
DAY 25 — FILE UPLOAD SECURITY VALIDATOR
============================================================
Input directory : input
Audit log       : output/logs/upload-audit.jsonl
Report directory: output/reports

[ACCEPT] valid.jpg            File signature validated as JPEG and matches the upload policy.
[ACCEPT] valid.png            File signature validated as PNG and matches the upload policy.
[REJECT] fake.jpg             File signature is unknown or unsupported.
[REJECT] fake.png             File signature is unknown or unsupported.
[REJECT] unknown.txt          File extension is not allowlisted: .txt

------------------------------------------------------------
[+] JSON report : output/reports/day25-report.json
[+] TXT report  : output/reports/day25-report.txt
[+] Audit log   : output/logs/upload-audit.jsonl
------------------------------------------------------------
```

Final clean-run summary:

```text
Total events : 5
Accepted     : 2
Rejected     : 3
Stored       : 2
Not stored   : 3
```

---

## Command-Line Options

The CLI supports custom input and output locations.

### Custom Input Directory

```bash
python3 -m scanner.cli --input-dir /path/to/uploads
```

### Custom Audit Log

```bash
python3 -m scanner.cli \
    --log /path/to/upload-audit.jsonl
```

### Custom Report Directory

```bash
python3 -m scanner.cli \
    --report-dir /path/to/reports
```

### Combined Example

```bash
python3 -m scanner.cli \
    --input-dir input \
    --log output/logs/upload-audit.jsonl \
    --report-dir output/reports
```

---

## Generated Artifacts

After execution, the validator generates:

```text
output/
├── logs/
│   └── upload-audit.jsonl
│
└── reports/
    ├── day25-report.json
    └── day25-report.txt
```

### Audit Log

View the JSONL audit log:

```bash
cat output/logs/upload-audit.jsonl
```

### Text Report

```bash
cat output/reports/day25-report.txt
```

### JSON Report

For formatted JSON output:

```bash
python3 -m json.tool output/reports/day25-report.json
```

---

## Testing Strategy

The project uses automated unit and security-boundary tests covering the complete validation pipeline.

Test areas include:

| Component         | Purpose                                  |
| ----------------- | ---------------------------------------- |
| Models            | Validate security-domain data structures |
| Configuration     | Enforce secure upload policy             |
| Signatures        | Detect approved magic bytes              |
| Validator         | Apply upload validation rules            |
| Storage           | Enforce safe storage decisions           |
| Logging           | Validate structured audit events         |
| Reporting         | Validate generated security reports      |
| Pipeline          | Validate end-to-end processing           |
| Security Boundary | Validate adversarial upload scenarios    |

Current validation status:

```text
Full test suite       : 58 passed
Security-boundary     : 5 passed
git diff --check       : clean
```

---

## Security Test Cases

The project includes controlled adversarial scenarios.

### Fake JPEG

A non-JPEG file is named:

```text
fake.jpg
```

Expected:

```text
REJECT
```

### Fake PNG

A non-PNG file is named:

```text
fake.png
```

Expected:

```text
REJECT
```

### Unsupported Extension

A plain text file is submitted as:

```text
unknown.txt
```

Expected:

```text
REJECT
```

### Signature/Extension Mismatch

A JPEG signature is placed inside a `.png` file.

Expected:

```text
REJECT
```

These scenarios demonstrate why filename extensions should never be considered authoritative proof of file type.

---

## Security Recommendations

Magic-byte validation is useful but **must not be treated as a complete malware-detection mechanism**.

Production deployments should implement defense in depth.

### Recommended controls

1. **Use an extension allowlist**

   * Permit only formats required by the application.

2. **Validate file signatures**

   * Inspect magic bytes rather than trusting the filename.

3. **Validate file structure**

   * Parse supported formats with trusted libraries where appropriate.

4. **Enforce upload-size limits**

   * Prevent unnecessarily large files from consuming resources.

5. **Generate server-side filenames**

   * Do not use attacker-controlled filenames as storage paths.

6. **Store uploads outside executable web roots**

   * Uploaded content should not be directly executable.

7. **Disable script execution in upload directories**

   * Prevent uploaded scripts from being interpreted by the server.

8. **Use least-privilege filesystem permissions**

   * Restrict the application and upload directory to the minimum required permissions.

9. **Consider content reprocessing**

   * For images and other suitable formats, decode and re-encode content using trusted libraries.

10. **Log validation decisions**

    * Maintain sufficient audit information for monitoring and investigation.

11. **Monitor repeated failures**

    * Multiple rejected uploads may indicate probing or abuse.

12. **Never execute uploaded files**

    * Treat user-uploaded content as untrusted data.

---

## Important Security Limitation

A valid magic-byte signature does **not** prove that a file is harmless.

For example, a file can begin with a valid image signature while containing unexpected data elsewhere in the file.

Therefore:

```text
Magic Bytes
     ≠
Complete Security Validation
```

A production-grade upload security architecture should combine:

```text
Extension Allowlisting
        +
Magic-Byte Validation
        +
Structural Validation
        +
Content Validation
        +
Size Limits
        +
Safe Storage
        +
Non-Executable Configuration
        +
Logging / Monitoring
        +
Access Control
```

---

## Secure Storage Principles

The storage layer follows these principles:

### Reject Before Storage

Invalid files must not receive a storage identifier.

```text
REJECT
  |
  +--> stored = false
  |
  +--> storage_name = null
```

### Server-Generated Names

Accepted files receive unpredictable server-generated identifiers.

### Non-Executable Storage

Uploaded content should be stored as data and should not be interpreted as application code.

### Separation of Validation and Storage

Validation determines whether the file satisfies the security policy. Storage preparation occurs only after successful validation.

---

## Safe Laboratory Use

This repository is intended for:

* Security education
* Secure-development training
* Defensive cybersecurity testing
* File-upload validation research
* Python security engineering practice
* Internship portfolio development

The supplied suspicious fixtures are intentionally harmless.

Do not replace them with real malware or use this project to upload, execute, or distribute malicious software.

Only test file-upload controls against systems and applications for which you have explicit authorization.

---

## Troubleshooting

### `pytest` command not found

Use:

```bash
python3 -m pytest -q
```

This ensures the test runner is executed using the active Python environment.

---

### Virtual environment is not active

Activate it with:

```bash
source .venv/bin/activate
```

Then verify:

```bash
python3 --version
```

---

### Reports contain duplicate events

The audit log uses append-only JSONL behavior.

If the CLI is executed multiple times, previous events remain in:

```text
output/logs/upload-audit.jsonl
```

For a clean demonstration run:

```bash
rm -f output/logs/upload-audit.jsonl
rm -f output/reports/day25-report.json
rm -f output/reports/day25-report.txt
python3 -m scanner.cli
```

The clean run should produce five validation events.

---

## Evidence

Recommended evidence for this laboratory includes:

1. Full automated test suite showing `58 passed`
2. Security-boundary test suite showing `5 passed`
3. CLI runtime showing accepted and rejected files
4. Generated text security report
5. JSONL audit log demonstrating storage decisions
6. Project structure showing the implemented architecture

---

## Documentation

Detailed technical documentation is available in:

```text
report/day25-report.md
```

The report provides:

* Executive summary
* Threat model
* Security architecture
* Implemented controls
* Runtime results
* Adversarial testing
* Mitigation recommendations
* Security limitations
* Final assessment

---

## GitHub

### Repository

The complete internship project is maintained in the project's GitHub repository.

Clone it with:

```bash
git clone https://github.com/Luffy-Sensei/cyber-internship.git
```

Then:

```bash
cd cyber-internship-FINAL/day25-file-upload-validator
```

### Download

From the GitHub repository page:

```text
Code → Download ZIP
```

Then extract the archive and open:

```text
day25-file-upload-validator/
```
---

## License

Add the project's applicable license here if the parent repository is licensed.

If no license has been selected, the repository should not be assumed to grant permission for redistribution or commercial use.

---

## Project Status

**Day 25 — Complete**

Validation status:

```text
[✓] Upload models implemented
[✓] Secure upload policy implemented
[✓] Magic-byte detection implemented
[✓] Extension validation implemented
[✓] Signature/extension consistency implemented
[✓] File-size enforcement implemented
[✓] Safe storage policy implemented
[✓] Server-generated filenames implemented
[✓] Structured audit logging implemented
[✓] JSON reporting implemented
[✓] Text reporting implemented
[✓] End-to-end pipeline implemented
[✓] CLI implemented
[✓] Security-boundary tests implemented
[✓] Runtime validation completed
[✓] 58 automated tests passing
[✓] Final evidence generated
```

---

## Author

**Cyber Internship — Day 25**

Focus:

```text
Secure File Upload Validation
Magic-Byte Detection
Defensive Security Engineering
```
