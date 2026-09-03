# Day 25 — File Upload Vulnerability & Magic Bytes Validator

## 1. Executive Summary

Day 25 implemented a defensive file-upload security validation pipeline designed to reduce the risk of malicious or improperly formatted files bypassing extension-based upload controls.

The laboratory demonstrates how an application can validate the actual binary signature of uploaded files using **magic bytes**, rather than trusting the filename extension alone. The implementation supports controlled PNG and JPEG validation and rejects files whose content does not match an approved file format.

The solution also incorporates additional security controls including:

* File-extension allowlisting
* Magic-byte signature validation
* Extension/signature consistency checking
* Maximum upload-size enforcement
* Server-generated storage filenames
* Disabled preservation of original filenames
* Non-executable upload storage classification
* Rejection before storage
* Structured JSONL security auditing
* JSON and human-readable security reporting
* Automated adversarial/security-boundary testing

All controlled fixtures used during testing were harmless mock files. No real malicious payloads were executed or processed.

---

## 2. Objective

The objective of this laboratory was to implement a defensive file-upload validator capable of identifying files that attempt to bypass extension-based validation.

A common insecure pattern is:

```text
if filename.endswith(".jpg"):
    accept_file()
```

This approach trusts attacker-controlled metadata and does not verify that the file actually contains JPEG data.

The implemented validator instead examines the beginning of the file and compares its binary signature against known approved signatures.

The laboratory focuses on the following security principle:

> File type validation should be based on file content and an explicit security policy rather than filename extension alone.

---

## 3. Threat Model

The validator addresses upload scenarios where an attacker may attempt to submit:

1. A script renamed with an image extension.
2. A JPEG file renamed as a PNG.
3. An unsupported file type using an allowed-looking filename.
4. An oversized upload intended to consume application resources.
5. A file using an original filename that could create unsafe storage behavior.

Example controlled bypass:

```text
malicious script
      |
      v
rename to fake.jpg
      |
      v
extension-only validator
      |
      v
incorrectly accepted
```

The implemented security pipeline instead performs content validation before a file becomes eligible for storage.

---

## 4. Security Architecture

The Day 25 implementation is organized into several security-focused components:

```text
                    Uploaded File
                         |
                         v
                +------------------+
                | UploadValidator  |
                +------------------+
                         |
             +-----------+-----------+
             |           |           |
             v           v           v
          Size       Extension    Magic Bytes
          Check       Check        Detection
             |           |           |
             +-----------+-----------+
                         |
                         v
                Extension/Signature
                     Consistency
                         |
                 +-------+-------+
                 |               |
              ACCEPT           REJECT
                 |               |
                 v               v
          SafeStorage        No Storage
                 |               |
                 v               v
       Server-generated       Audit Log
          filename                |
                 |                v
                 +---------> Reporting
```

The pipeline ensures that validation occurs before storage preparation.

---

## 5. Implemented Security Controls

### 5.1 Extension Allowlisting

The upload policy explicitly allows only approved extensions:

```text
.png
.jpg
.jpeg
```

Unsupported extensions such as:

```text
.txt
.php
.sh
.exe
```

are rejected.

This provides a first layer of defense against arbitrary file types.

---

### 5.2 Magic-Byte Validation

The validator checks the binary header of the uploaded file.

Supported signatures include:

| File Type | Signature                 |
| --------- | ------------------------- |
| PNG       | `89 50 4E 47 0D 0A 1A 0A` |
| JPEG      | `FF D8 FF`                |

Only the required file header is read for signature detection.

The validator does not execute, interpret, or otherwise run uploaded file contents.

---

### 5.3 Extension and Signature Consistency

The implementation does not rely on either extension validation or magic-byte detection independently.

Both must agree when extension matching is enabled.

For example:

```text
Filename: image.png
Detected content: JPEG
Result: REJECT
```

This prevents a valid file signature from simply being paired with an incorrect allowlisted extension.

---

### 5.4 Maximum File Size

The default upload policy limits files to:

```text
5 MiB
```

The validator compares the actual file size against the configured policy before processing the file header.

This reduces exposure to unnecessarily large uploads and provides a basic resource-consumption control.

---

### 5.5 Server-Generated Storage Names

Accepted uploads receive a server-generated filename using a UUID-based identifier.

Example concept:

```text
original: valid.jpg

stored as:

<server-generated-id>.jpg
```

This prevents the application from directly using attacker-controlled original filenames as storage identifiers.

---

### 5.6 Original Filename Preservation Disabled

The default policy does not preserve the original filename as the storage identifier.

This reduces risks associated with:

* Path manipulation
* Filename collisions
* Unsafe characters
* Application-specific filename interpretation
* Predictable storage paths

The original filename remains available for audit information but is not used as the generated storage name.

---

### 5.7 Non-Executable Upload Storage

The configured storage class is:

```text
NON_EXECUTABLE_UPLOAD_STORAGE
```

The design explicitly treats accepted uploads as data rather than executable application resources.

The storage component prepares a safe storage decision but does not perform arbitrary execution or dynamic interpretation of uploaded files.

---

### 5.8 Rejection Before Storage

Rejected validation results cannot receive a storage filename.

For rejected files:

```text
stored       = false
storage_name = null
```

This establishes an explicit security boundary between validation and storage.

---

### 5.9 Structured Security Logging

Each validation event is recorded in JSONL format.

The audit record contains security-relevant metadata including:

* Timestamp
* Filename
* Validation action
* Validation status
* Rejection/acceptance reason
* Detected file type
* File size
* Storage decision
* Generated storage name
* Storage classification

File contents are not written to the audit log.

---

## 6. Controlled Test Fixtures

The laboratory uses harmless mock fixtures representing benign and suspicious uploads.

### Benign fixtures

```text
input/benign/valid.png
input/benign/valid.jpg
```

These contain valid PNG/JPEG signatures followed by mock data.

### Security-test fixtures

```text
input/malicious/fake.jpg
input/malicious/fake.png
input/malicious/unknown.txt
```

These files are controlled test artifacts and do not contain functional malicious payloads.

The purpose is to reproduce the security condition in a safe laboratory environment.

---

## 7. Runtime Validation Results

The final clean runtime execution processed five controlled files.

### Results

| File          | Result | Reason                        |
| ------------- | ------ | ----------------------------- |
| `valid.jpg`   | ACCEPT | JPEG signature validated      |
| `valid.png`   | ACCEPT | PNG signature validated       |
| `fake.jpg`    | REJECT | Unknown/unsupported signature |
| `fake.png`    | REJECT | Unknown/unsupported signature |
| `unknown.txt` | REJECT | Extension not allowlisted     |

Final execution summary:

```text
Total events : 5
Accepted     : 2
Rejected     : 3
Stored       : 2
Not stored   : 3
```

The results demonstrate that files with benign-looking image extensions are not automatically trusted.

---

## 8. Adversarial Security Testing

A dedicated security-boundary test suite was implemented to verify that common upload-validation bypass attempts do not cross the storage boundary.

The adversarial test suite contains five tests.

### Test 1 — Fake JPEG Rejection

A mock shell-script-style file is given a `.jpg` extension.

Expected behavior:

```text
REJECT
stored = false
storage_name = null
```

This confirms that the extension alone cannot bypass content validation.

---

### Test 2 — Extension-Only Bypass

A mock PHP-style file is renamed with a `.jpg` extension.

Expected behavior:

```text
REJECT
detected_type = None
```

This verifies that the validator does not interpret the filename extension as proof of file type.

---

### Test 3 — Signature/Extension Mismatch

A JPEG signature is placed in a file named:

```text
image.png
```

Expected behavior:

```text
REJECT
```

This confirms that detected content must correspond with the declared extension when extension matching is required.

---

### Test 4 — Rejected Files Receive No Storage Name

A rejected validation result is passed directly to the storage component.

Expected behavior:

```text
stored = False
storage_name = None
```

This verifies the rejection-before-storage boundary.

---

### Test 5 — Valid Upload Gets a Server-Generated Name

A valid mock JPEG is submitted.

Expected behavior:

```text
ACCEPT
stored = True
storage_name != None
```

This confirms that accepted uploads are prepared using a server-generated storage identifier.

---

## 9. Automated Test Results

The dedicated adversarial security suite completed successfully:

```text
5 passed
```

The complete Day 25 automated test suite completed successfully:

```text
58 passed in 0.52s
```

Repository whitespace validation also completed successfully:

```text
git diff --check
```

No whitespace errors were reported.

The test coverage validates the individual models, configuration, signature detection, validation logic, storage policy, logging, reporting, pipeline integration, and security-boundary behavior.

---

## 10. Reporting and Audit Artifacts

The runtime pipeline produces the following artifacts:

```text
output/
├── logs/
│   └── upload-audit.jsonl
└── reports/
    ├── day25-report.json
    └── day25-report.txt
```

### JSONL Audit Log

The JSONL log provides structured machine-readable security events suitable for further analysis or integration with monitoring systems.

### JSON Report

The JSON report provides structured summary information and validation events.

### Text Report

The text report provides an analyst-friendly summary of:

* Total validation events
* Accepted files
* Rejected files
* Storage decisions
* Individual validation results

---

## 11. Why Magic Bytes Alone Are Not Sufficient

Magic-byte validation is an important security control, but it does not prove that an uploaded file is completely safe.

A file can contain a valid image signature while still containing unexpected or malicious content later in the file.

Therefore, production systems should use layered validation.

Recommended controls include:

```text
Extension Allowlist
        +
Magic-Byte Validation
        +
Structural Parsing
        +
Content Validation
        +
File Size Limits
        +
Safe Storage
        +
Server-Generated Names
        +
Access Control
        +
Logging/Monitoring
```

For formats that require deeper validation, applications should parse the file using trusted libraries and reject malformed or unexpected structures.

---

## 12. Production Mitigation Recommendations

For a production upload service, the following controls are recommended.

### 12.1 Store uploads outside the executable web root

Uploaded files should not be placed in directories where the web server can execute them as scripts.

---

### 12.2 Disable script execution in upload locations

Even if an attacker manages to upload a file containing executable syntax, the storage environment should prevent the web server or application runtime from interpreting it as executable code.

---

### 12.3 Generate storage identifiers server-side

Applications should not directly use user-controlled filenames as filesystem paths.

Server-generated identifiers should be used for storage.

---

### 12.4 Apply strict file-size limits

Upload limits should be appropriate for the application's legitimate requirements.

Limits should be enforced before expensive processing.

---

### 12.5 Validate the complete file structure where practical

For complex formats, applications should perform structural validation rather than relying solely on the first few bytes.

---

### 12.6 Consider content reprocessing

Where appropriate, uploaded images can be decoded and re-encoded using a trusted image-processing pipeline.

This can remove unexpected metadata or embedded content and produce a normalized representation.

---

### 12.7 Apply least-privilege permissions

The upload storage directory should have the minimum filesystem permissions required by the application.

The application process should not receive unnecessary execution privileges.

---

### 12.8 Maintain security audit logs

Validation failures should be logged with sufficient context to support:

* Incident investigation
* Abuse detection
* Operational monitoring
* Security analytics

Sensitive file contents should not be written to logs.

---

### 12.9 Monitor repeated upload failures

Repeated attempts to submit invalid or suspicious files may indicate automated probing or abuse.

Production systems should consider rate limiting and monitoring repeated failures.

---

## 13. Security Limitations

This laboratory intentionally provides a focused demonstration of upload validation rather than a complete production malware-analysis platform.

The implementation does not attempt to provide:

* Antivirus scanning
* Full MIME/content classification
* Deep image parsing
* Archive extraction security
* Malware sandboxing
* Content disarm and reconstruction
* Cloud object-storage integration
* Web-server configuration enforcement

These controls may be appropriate depending on the production application's threat model.

---

## 14. Security Principles Demonstrated

Day 25 demonstrates several important secure-development principles:

### Never trust client-controlled metadata

A filename extension is supplied by the uploader and should not be treated as authoritative.

### Validate before processing

Files should be validated before entering downstream processing or storage workflows.

### Use defense in depth

Multiple independent controls provide stronger protection than a single validation mechanism.

### Separate data from executable resources

User-uploaded content should be stored in a location and configuration where it cannot be executed as application code.

### Maintain an audit trail

Security decisions should be observable and reviewable.

### Fail closed

When the validator cannot establish that a file matches an approved policy, it rejects the upload rather than assuming it is safe.

---

## 15. Conclusion

The Day 25 File Upload Vulnerability & Magic Bytes Validator successfully demonstrates a layered defensive approach to insecure file-upload handling.

The implementation rejects extension-based bypass attempts, verifies supported file signatures, enforces extension/signature consistency, applies file-size restrictions, prevents rejected files from reaching storage preparation, and uses server-generated storage identifiers for accepted files.

Final validation produced:

```text
58 automated tests passed
5 security-boundary tests passed
2 files accepted
3 files rejected
2 files eligible for safe storage
3 files prevented from storage
```

The laboratory confirms that **file extension validation alone is insufficient** and demonstrates how magic-byte inspection can form one component of a broader secure upload architecture.

The final design follows a defense-in-depth model in which uploaded content must satisfy multiple independent security requirements before it becomes eligible for non-executable storage.
