# Executive & Technical Incident Response Report
**Document Title:** Automated Social Engineering Incident Response & Containment Framework   
**Program:** Cybersecurity Internship — Phase 1 (Day 14)  
**Classification:** Confidential / Internal Security Document  

---

## 1. Executive Summary

Social engineering attacks—specifically spear-phishing, credential harvesting, and Multi-Factor Authentication (MFA) fatigue—remain the primary entry vectors for enterprise initial access. The traditional manual triage process introduces significant delay, allowing adversaries to move laterally, exfiltrate sensitive data, or establish persistent access via malicious inbox rules.

This report documents the architecture, operational workflow, and technical validation of an automated **Security Orchestration, Automation, and Response (SOAR)** Incident Response (IR) engine. Aligned with the **NIST SP 800-61 Rev. 2** Computer Security Incident Handling Guide, the tool automatically executes critical containment actions—such as identity locking, session token revocation, mailbox quarantines, and host isolations—in under **5 seconds** post-alert, drastically reducing the enterprise **Mean Time to Respond (MTTR)**.

---

## 2. NIST SP 800-61 Incident Lifecycle Alignment

The automated framework structures its operations around the four primary phases of the NIST incident response lifecycle:

┌────────────────────────────────────────────────────────┐
│                      1. PREPARATION                    │
│  • SIEM/EDR Ingestion Rules  • SOAR Playbook Mapping   │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│              2. DETECTION & ANALYSIS                   │
│  • Real-time Alert Trigger   • Vector & Severity Eval  │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│             3. CONTAINMENT, ERADICATION & RECOVERY     │
│  • Identity Lockout & Token Revocation                 │
│  • Mailbox Quarantine & Host Network Isolation         │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│                  4. POST-INCIDENT ACTIVITY             │
│  • JSON Telemetry Logging   • Root Cause Analysis     │
└────────────────────────────────────────────────────────┘

### Incident Handling Stages
1. **Preparation:** Deployment of predefined Python-based containment playbooks mapped directly to identity provider (IdP) APIs, email gateways, and endpoint detection engines.
2. **Detection & Analysis:** Parsing inbound security alerts to categorize the attack vector (`phishing`, `vishing`, `mfa_fatigue`, `usb_baiting`) and assign a severity rating (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
3. **Containment, Eradication & Recovery:** Immediate execution of automated containment protocols to isolate the threat vector, followed by credential resets and artifact purging.
4. **Post-Incident Activity:** Immutable, audit-ready JSON logging containing time-stamped evidence of all response actions for compliance, insurance, and legal reviews.

---

## 3. Playbook Mapping & Containment Matrix

The SOAR engine applies a dual-layered response strategy: baseline identity protection for all high-severity threats, combined with tailored playbooks for specific attack vectors.

| Attack Vector | Severity Level | Automated Containment Actions | Target Systems |
| :--- | :--- | :--- | :--- |
| **Phishing / BEC** | `HIGH` / `CRITICAL` | • Lock user Active Directory/IdP account<br>• Revoke active OAuth/JWT tokens<br>• Tenant-wide email quarantine<br>• Perimeter block on source IP/Domain<br>• Submit payloads to sandbox | Active Directory, Exchange/O365, Perimeter Firewall |
| **MFA Fatigue** | `HIGH` / `CRITICAL` | • Force global user session termination<br>• Require WebAuthn/FIDO2 hardware key<br>• Temporarily restrict push-notifications<br>• Trigger mandatory password reset | Okta / Azure AD (Entra ID), MFA Gateway |
| **USB Baiting / HID** | `CRITICAL` | • Execute host network isolation<br>• Trigger EDR memory & process tree scan<br>• Push GPO policy to block physical USB ports | EDR Agent, Host Firewall, Group Policy |
| **Vishing** | `MEDIUM` | • Flag targeted telephone extension<br>• Notify SOC voice/telephony team<br>• Broadcast spoofed caller ID warning | VoIP / PBX Server, SOC Dashboard |

---

## 4. Technical Validation & Forensic Telemetry

To verify the engine's execution integrity, simulated high-severity phishing alerts were processed through the pipeline.

### Tested Incident Payload
```json
{
  "type": "phishing",
  "severity": "HIGH",
  "user": "riya@sqrock.com"
}
Generated Audit Telemetry (output/ir_response_report.json)
JSON
{
    "incident_id": "INC-1724408105",
    "execution_timestamp": "2026-08-23 10:15:05",
    "incident_details": {
        "vector_type": "phishing",
        "severity_level": "HIGH",
        "affected_target": "riya@sqrock.com"
    },
    "total_actions_executed": 8,
    "containment_actions": [
        "Lock user account in Active Directory / Identity Provider",
        "Revoke active OAuth/JWT authentication tokens",
        "Preserve system memory and access logs for forensic audit",
        "Notify Incident Response Lead and CISO",
        "Quarantine target email across all tenant mailboxes",
        "Block sender domain and source IP on perimeter firewalls",
        "Submit suspicious attachments/URLs to automated sandbox",
        "Search mail logs for additional recipient instances"
    ],
    "status": "CONTAINED"
}
5. Security Operations Center (SOC) Recommendations
API Integration Hardening: Connect the automation engine directly to enterprise identity management APIs (e.g., Microsoft Graph API, Okta API) using secure, least-privilege service principals.

Immutable Audit Storage: Write output telemetry directly to write-once-read-many (WORM) storage or dedicated SIEM indexers to prevent tamper risks during post-compromise investigations.

Automated Recovery Playbooks: Expand the framework to automate the recovery phase—enabling automated account un-locking following mandatory out-of-band identity verification.
