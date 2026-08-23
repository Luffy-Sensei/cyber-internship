# Day 14: Automated Social Engineering Incident Response (SOAR Engine)

## Project Overview
This project delivers a production-grade **Security Orchestration, Automation, and Response (SOAR)** execution engine tailored for handling social engineering threat vectors (Phishing, Vishing, MFA Fatigue, USB Baiting). Aligned with the **NIST SP 800-61** Incident Response framework, the script minimizes **Mean Time to Respond (MTTR)** by executing instant containment procedures—such as account lockouts, session token revocations, email quarantines, and network host isolations—the moment high-severity alerts are detected.

---

## NIST SP 800-61 Incident Response Workflow
┌──────────────────────┐
│    1. PREPARATION    │  <-- Playbooks, SOAR Tools & Identity Provider Access
└──────────┬───────────┘
│
▼
┌──────────────────────┐
│  2. IDENTIFICATION   │  <-- Alert Ingestion (SIEM, EDR, User Reports)
└──────────┬───────────┘
│
▼
┌──────────────────────┐
│    3. CONTAINMENT    │  <-- Automated Account Lockout, Token Revocation & Isolation
└──────────┬───────────┘
│
▼
┌──────────────────────┐
│4. ERADICATION/RECOVERY│ <-- Credential Reset, Mail Purging & Host Re-imaging
└──────────┬───────────┘
│
▼
┌──────────────────────┐
│  5. LESSONS LEARNED  │  <-- JSON Telemetry Audit Log & Post-Mortem Analysis
└──────────────────────┘


---

## Directory Architecture

day14-se-incident-response/
├── input/                      # Input trigger payloads
│   └── sample_incident.json
├── output/                     # Exported JSON IR containment records
│   └── ir_response_report.json
├── report/                     # Executive & Technical documentation
│   └── day14-report.md
├── screenshots/                # Visual execution proofs
├── requirements.txt            # System dependencies
├── README.md                   # Project documentation
└── ir_automation_engine.py     # Core SOAR execution script


---

## Key Features & Capabilities

* **Automated Containment Rules:** Executes baseline isolation actions for all `HIGH` and `CRITICAL` severity incidents.
* **Vector-Specific Playbooks:**
  * **Phishing / BEC:** Tenant-wide email quarantine, domain/IP perimeter blocking, sandbox submission.
  * **MFA Fatigue:** Immediate session termination, push-MFA restriction, password reset trigger.
  * **USB Baiting:** Host network isolation, EDR memory scan, physical port blocking policy.
  * **Vishing:** Telephony extension monitoring and SOC broadcast alerts.
* **Audit-Ready Telemetry:** Automatically exports structured JSON containment records complete with timestamps, unique incident IDs, executed actions, and target metadata.

---

## Quickstart & Usage

### 1. Requirements Setup
This tool uses standard Python library modules (`os`, `sys`, `json`, `argparse`, `datetime`). Ensure your virtual environment is active:
```bash
source ../venv/bin/activate
2. Run Phishing Incident Containment Playbook
Bash
python3 ir_automation_engine.py --type phishing --severity HIGH --user riya@sqrock.com
3. Run MFA Fatigue Containment Playbook
Bash
python3 ir_automation_engine.py --type mfa_fatigue --severity CRITICAL --user admin@sqrock.com
Example Console Output
Plaintext
======================================================================
 [*] DAY 14: AUTOMATED INCIDENT RESPONSE ENGINE (SOAR)
======================================================================
 Incident ID  : INC-1724408105
 Time         : 2026-08-23 10:15:05
 Vector Type  : PHISHING
 Severity     : HIGH
 Target User  : riya@sqrock.com
----------------------------------------------------------------------
Automated Containment Actions Executed:
  [✓] Lock user account in Active Directory / Identity Provider
  [✓] Revoke active OAuth/JWT authentication tokens
  [✓] Preserve system memory and access logs for forensic audit
  [✓] Notify Incident Response Lead and CISO
  [✓] Quarantine target email across all tenant mailboxes
  [✓] Block sender domain and source IP on perimeter firewalls
  [✓] Submit suspicious attachments/URLs to automated sandbox
  [✓] Search mail logs for additional recipient instances

======================================================================
[*] IR Audit Record exported to: output/ir_response_report.json
Compliance & Legal
Generated reports from this framework serve as evidence for regulatory compliance frameworks (ISO/IEC 27001, SOC 2 Type II, GDPR) and cybersecurity insurance reporting requirements following a suspected breach.
