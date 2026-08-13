
### 2. Personal report

Your `report/day04-report.md` should be the **detailed technical record**, not just a copy of the README.

Use this structure:

```markdown
# Day 04 — Vishing & Smishing Awareness Engine
## Detailed Technical Report

**Phase:** Phase 1
**Day:** 04
**Topic:** Vishing & Smishing Simulation Scripts
**Difficulty:** Beginner

---

## 1. Objective

The objective of Day 04 was to build a Python-based social-engineering
awareness engine capable of generating vishing and smishing training
scenarios.

The engine demonstrates how social-engineering scenarios can combine
impersonation, psychological triggers, urgency, suspicious requests, and
other warning signs.

---

## 2. Theory

### Vishing

Vishing is voice phishing conducted through telephone calls.

The generated scenario demonstrates:

- Authority impersonation
- Fear
- Rapport/l​iking
- Urgency
- Requests for sensitive information
- Pressure tactics

### Smishing

Smishing is phishing conducted through SMS or text messaging.

The generated scenario demonstrates:

- Sender impersonation
- Suspicious links
- Urgency
- Scarcity
- Account/security pretexts

---

## 3. Psychological Triggers

The engine models:

### Authority

The scenario establishes credibility by presenting the caller or sender
as a trusted authority.

### Fear

The recipient is presented with a potential negative consequence.

### Urgency

The recipient is encouraged to act immediately instead of independently
verifying the request.

### Scarcity

An artificial time limitation or limited opportunity is introduced.

### Liking

Friendly communication and rapport are used to increase perceived
trustworthiness.

---

## 4. Engine Architecture

The generator accepts scenario parameters and produces structured
awareness-training records.

Each generated scenario contains:

- Scenario metadata
- Channel information
- Impersonated role
- Pretext
- Psychological triggers
- Scenario script
- Red flags
- Defensive guidance
- Quiz questions

The results are exported to JSON and text formats.

---

## 5. Vishing Scenario

### Scenario Type

Vishing / Voice Call

### Impersonated Role

Government Agent

### Pretext

Security Breach Alert

### Psychological Triggers

- Authority
- Fear
- Liking

### Red Flags

1. Credential request
2. Unexpected contact
3. Authority impersonation
4. Urgency or pressure
5. Threats of consequences

### Defensive Guidance

- Never disclose passwords or authentication codes.
- Verify the caller independently.
- Do not trust caller ID alone.
- Take time to evaluate unexpected requests.
- Report suspicious calls.

---

## 6. Smishing Scenario

### Scenario Type

Smishing / SMS

### Impersonated Role

Account Security Team

### Pretext

Package Delivery Failed / Account Security Alert

### Psychological Triggers

- Authority
- Urgency
- Scarcity

### Red Flags

1. Suspicious link
2. Unexpected message
3. Urgency or pressure
4. Sender impersonation
5. Suspicious reward/consequence framing

### Defensive Guidance

- Do not click unexpected links.
- Verify through official applications or websites.
- Do not reply to suspicious messages.
- Block and report suspicious messages.
- Use appropriate carrier or organizational reporting mechanisms.

---

## 7. Generated Statistics

The engine generated:

| Metric | Result |
|---|---:|
| Total scenarios | 2 |
| Vishing scenarios | 1 |
| Smishing scenarios | 1 |
| Total red flags | 10 |
| Defensive guidance items | 10 |
| Quiz questions | 6 |

Psychological trigger usage:

| Trigger | Count |
|---|---:|
| Authority | 2 |
| Fear | 1 |
| Liking | 1 |
| Scarcity | 1 |
| Urgency | 1 |

---

## 8. Output Validation

JSON validation:

```bash
jq empty output/awareness_scenarios.json
Result:

JSON VALID

Python syntax validation:

python3 -m py_compile se_script_generator.py

Result:

No errors

Git formatting validation:

git diff --check

Result:

No errors
9. Security Lessons

This exercise demonstrated that social engineering does not necessarily
depend on sophisticated technical exploitation.

A convincing pretext combined with authority, fear, urgency, scarcity, or
rapport can influence a recipient's decision-making.

Important defensive principles include:

Verify unexpected requests independently.
Never disclose authentication secrets to unsolicited callers.
Treat unexpected SMS links as suspicious.
Do not allow urgency to bypass verification.
Use official contact channels instead of information supplied by the
suspicious message or caller.
Report suspicious social-engineering attempts.
10. Evidence

The following screenshots document the completed exercise:

Scanner execution
Generated vishing scenario
Generated smishing scenario
Structured JSON report
11. Conclusion

Day 04 successfully demonstrated the construction of a Python-based
social-engineering awareness generator.

The completed engine produces structured vishing and smishing scenarios,
identifies psychological manipulation techniques, documents red flags,
provides defensive guidance, and generates knowledge-check questions.

The exercise strengthened understanding of the human and psychological
components of cybersecurity attacks and the importance of verification,
skepticism, and security awareness.
