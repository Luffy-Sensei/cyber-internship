# Day 24 — Authorized Target & Deployment Guide

## Automated Threat Intelligence IP Blocking Pipeline

---

## 1. Purpose

This document defines how the Day 24 threat-intelligence pipeline may be used when the laboratory is extended beyond its controlled local environment.

The project is designed primarily as a **defensive security automation laboratory**.

The default implementation uses:

* Controlled local fixtures.
* Synthetic threat-intelligence data.
* Record-level validation.
* Risk-based policy evaluation.
* Firewall `DRY-RUN` execution.
* Automated regression testing.

The default configuration does **not** modify the host firewall.

Any extension to an external, remote, cloud, enterprise, or production environment requires explicit authorization and appropriate change-management controls.

---

# 2. Authorization Requirement

Before using this project with any target system, network, firewall, threat-intelligence service, or external infrastructure, obtain explicit authorization from the system owner or responsible security authority.

Authorization should identify:

* Target system or environment.
* IP addresses/CIDR ranges where applicable.
* Network or cloud account.
* Firewall/device being evaluated.
* Testing window.
* Approved activities.
* Prohibited activities.
* Responsible owner.
* Emergency contact.
* Rollback procedure.

Do not infer authorization merely because a system is:

* Reachable.
* Publicly accessible.
* Owned by the organization.
* Located on the same network.
* Discoverable through DNS.
* Listed in a threat-intelligence feed.

For production environments, the authorized scope should be documented before execution.

---

# 3. Important Day 24 Architecture Note

Day 24 is fundamentally a **threat-intelligence processing and firewall-policy orchestration pipeline**.

It is not a general-purpose network scanner.

The normal flow is:

```text
Threat Intelligence Feed
          |
          v
       Ingestion
          |
          v
      Validation
          |
          v
     Policy Engine
          |
          v
   Firewall Decision
          |
          v
   Firewall Adapter
          |
          v
      DRY-RUN
```

Therefore, there is no single `TARGET = "127.0.0.1"` variable that should simply be replaced to use another environment.

The components that depend on the target/environment should be changed deliberately.

---

# 4. Default Laboratory Target

The default laboratory environment is intentionally controlled.

Threat intelligence is supplied through local fixture files:

```text
input/mock-threat-feed.json
input/validation-threat-feed.json
```

Firewall behavior is simulated through:

```text
scanner/firewall.py
```

The firewall adapter produces structured execution records but does not modify the operating-system firewall.

This behavior should remain the default for development and testing.

---

# 5. If Using an Authorized External Environment

If an organization authorizes use of the pipeline against another environment, do **not** modify random source files.

Use the following dependency map.

| Requirement                 | Primary File                              | Purpose                          |
| --------------------------- | ----------------------------------------- | -------------------------------- |
| Pipeline thresholds         | `scanner/config.py`                       | Policy configuration             |
| Threat feed source          | `scanner/ingestion.py` / new feed adapter | Feed acquisition                 |
| Input fixtures              | `input/*.json`                            | Controlled testing data          |
| Risk policy                 | `scanner/policies.py`                     | BLOCK/MONITOR/IGNORE logic       |
| Firewall integration        | `scanner/firewall.py`                     | Execution boundary               |
| Validation                  | `scanner/validation.py`                   | Input security                   |
| Pipeline orchestration      | `scanner/validation_pipeline.py`          | Execution flow                   |
| Reports                     | `scanner/reporting.py`                    | Evidence generation              |
| Tests                       | `tests/`                                  | Regression/security verification |
| Authorization documentation | `authorized-target-guide.md`              | Scope and safety                 |
| Operational evidence        | `output/logs/` and `output/reports/`      | Audit trail                      |

The most important rule is:

> **Do not place production firewall commands directly into the policy engine or validation layer.**

The firewall integration should remain isolated behind an adapter.

---

# 6. What Should Be Changed for Another Authorized Threat Feed?

If the target environment uses a real or organizationally approved threat-intelligence feed, the preferred architecture is:

```text
External/Enterprise Feed
          |
          v
   Feed Adapter
          |
          v
 Authentication
          |
          v
 Integrity Validation
          |
          v
 Schema Validation
          |
          v
 Record Validation
          |
          v
 Policy Engine
```

The existing:

```text
scanner/ingestion.py
```

can remain responsible for parsing and validating normalized feed data.

For a professional implementation, introduce a separate feed adapter instead of mixing network communication into the existing parser.

Recommended structure:

```text
scanner/
├── feeds/
│   ├── __init__.py
│   ├── base.py
│   ├── mock.py
│   └── <approved_provider>.py
├── ingestion.py
├── validation.py
├── policies.py
├── firewall.py
└── reporting.py
```

The provider-specific module should convert external data into the internal `ThreatIndicator` representation.

This keeps the policy engine independent of the intelligence provider.

---

# 7. Do Not Hard-Code Production Targets

Avoid code such as:

```python
TARGET = "10.10.10.25"
```

or:

```python
FIREWALL_HOST = "192.168.1.1"
```

inside the application logic.

Instead, use explicit configuration.

For example:

```python
@dataclass(frozen=True)
class TargetConfig:
    environment: str
    authorized_targets: tuple[str, ...]
```

Then load the approved values from controlled configuration.

For a high-assurance implementation, target scope should be validated before execution.

---

# 8. Recommended Scope Allowlisting

A professional implementation should use an explicit allowlist rather than accepting arbitrary destinations.

For example:

```text
AUTHORIZED_ENVIRONMENT=lab
AUTHORIZED_TARGETS=192.0.2.0/24
```

The exact production ranges must come from the organization's authorization document.

Do not copy the example ranges into production.

The principle is:

```text
Requested Target
       |
       v
Is Target Authorized?
      / \
    YES  NO
     |    |
     v    v
 Continue  REJECT
```

OWASP recommends allowlisting identified and trusted network destinations where the application's required communication targets are known.

---

# 9. Recommended Code Change — Target Scope Validator

For a professional implementation, introduce:

```text
scanner/scope.py
```

Its responsibility should be limited to determining whether a requested environment or destination belongs to the authorized scope.

Example conceptual API:

```python
class ScopeViolation(ValueError):
    """Raised when a requested target is outside the authorized scope."""


class TargetScope:
    def __init__(self, authorized_networks):
        self.authorized_networks = authorized_networks

    def is_authorized(self, address):
        """Return True only when the address is explicitly authorized."""
        ...
```

The important design principle is that **scope validation happens before network or firewall activity**.

---

# 10. Do Not Use DNS as an Authorization Decision

Do not assume:

```text
hostname resolves → authorized
```

A hostname may resolve to an unexpected address.

For high-security deployments:

1. Validate the hostname format.
2. Resolve it through an approved resolver.
3. Validate all resulting addresses.
4. Compare them against the authorized scope.
5. Revalidate before sensitive execution where appropriate.

OWASP specifically recommends validating network destinations against known trusted applications and warns about DNS-related bypass scenarios.

---

# 11. Firewall Integration

The existing:

```text
scanner/firewall.py
```

should remain the **only logical boundary** between policy decisions and firewall execution.

Current architecture:

```text
FirewallDecision
       |
       v
FirewallAdapter
       |
       v
FirewallExecution
```

For a professional implementation, retain this abstraction.

Do not change:

```text
ThreatPolicy
```

into a component that directly calls:

```text
iptables
nft
firewalld
```

or vendor-specific firewall APIs.

Instead, create a dedicated adapter.

For example:

```text
scanner/firewall/
├── __init__.py
├── base.py
├── dry_run.py
└── <approved_firewall>.py
```

Conceptually:

```python
class FirewallBackend:
    def apply(self, rule):
        raise NotImplementedError
```

Then:

```text
ThreatPolicy
     |
     v
FirewallDecision
     |
     v
FirewallAdapter
     |
     +----> DryRunBackend
     |
     +----> AuthorizedProductionBackend
```

This makes testing substantially safer.

---

# 12. DRY-RUN Must Remain the Default

Even when a production backend exists:

```text
DRY_RUN = True
```

should remain the safe default.

Production execution should require an explicit configuration change.

Recommended deployment behavior:

```text
Default
   |
   v
DRY-RUN
```

Only after authorization, testing, approval, and change control:

```text
Approved Change
      |
      v
Production Backend
      |
      v
Controlled Execution
```

Never make production firewall modification the implicit behavior of the tool.

---

# 13. Recommended Production Safety Gate

A high-level implementation should require multiple conditions before an actual firewall operation is permitted.

For example:

```text
Target Authorized
       AND
Environment Approved
       AND
Feed Authenticated
       AND
Indicator Valid
       AND
Policy Decision = BLOCK
       AND
Change Approved
       AND
Execution Mode = APPLY
       |
       v
Allow Firewall Operation
```

If any condition fails:

```text
REJECT / DRY-RUN / NO ACTION
```

This provides defense in depth.

---

# 14. Never Trust Threat-Intelligence Data Blindly

A threat-intelligence feed should be treated as **untrusted input**.

Even when the provider is trusted, the data should be validated.

Recommended validation:

```text
IP Address
Indicator Type
Risk Score
Source
Timestamp
Expiration
Confidence
Feed Version
Schema
Duplicate Status
```

The current `ValidationEngine` already provides a foundation for this.

OWASP recommends strong allowlist-based validation for structured input rather than relying primarily on denylisting.

---

# 15. Recommended High-Level Data Model

For a professional deployment, consider expanding:

```python
ThreatIndicator
```

to include fields such as:

```text
ip
indicator
risk_score
confidence
source
first_seen
last_seen
expires_at
feed_id
feed_version
indicator_id
```

This enables better decisions about whether an indicator is still relevant.

For example:

```text
Risk = 98
Confidence = 0.99
Age = 4 hours
Source = Trusted Feed
Expiration = 20 hours
```

is substantially more useful than a single risk score.

---

# 16. Indicator Expiration

Do not create permanent blocks from temporary intelligence.

Recommended:

```text
Threat Indicator
      |
      v
Expiration Check
      |
      +---- expired ----> IGNORE
      |
      +---- active -----> Policy
```

A production `BlockRule` should ideally include an expiration or TTL.

Example conceptual model:

```python
@dataclass(frozen=True)
class BlockRule:
    ip: str
    indicator: str
    reason: str
    source: str
    expires_at: datetime
```

This reduces the risk of stale intelligence causing long-lived access-control problems.

---

# 17. Duplicate Detection

A professional implementation should detect duplicate indicators.

Example:

```text
103.45.67.89 / malware_c2
103.45.67.89 / malware_c2
103.45.67.89 / malware_c2
```

should not produce three independent firewall operations.

Recommended normalization:

```text
Raw Feed
   |
   v
Normalize
   |
   v
Deduplicate
   |
   v
Validate
   |
   v
Policy
```

---

# 18. Source Confidence

Do not make a firewall decision based solely on `risk_score`.

Consider:

```text
Risk Score
+
Source Trust
+
Confidence
+
Recency
+
Internal Evidence
```

For example:

```text
High Risk + Low Confidence
```

may be better handled as:

```text
MONITOR
```

rather than immediately generating a block proposal.

The exact policy should be determined by the organization's risk model.

---

# 19. Recommended Policy Enhancement

The current policy:

```text
90+  → BLOCK
70+  → MONITOR
<70  → IGNORE
```

is appropriate for the laboratory.

For a professional implementation, consider:

```text
BLOCK
MONITOR
IGNORE
ESCALATE
EXPIRE
ALLOWLIST_OVERRIDE
```

The policy engine should remain deterministic and testable.

Avoid embedding network or firewall operations into the policy engine.

---

# 20. Recommended Configuration Improvements

The current:

```text
scanner/config.py
```

should eventually support explicit environment configuration.

Recommended conceptual fields:

```python
@dataclass(frozen=True)
class PipelineConfig:
    environment: str
    dry_run: bool
    block_threshold: int
    monitor_threshold: int
    policy_name: str
    feed_source: str
    authorized_targets: tuple[str, ...]
    max_rules_per_run: int
    rule_ttl_seconds: int
```

Production values should be externally configurable and should not require source-code modification for routine deployment.

---

# 21. Recommended Secrets Handling

Never store:

```text
API keys
tokens
passwords
private keys
firewall credentials
```

inside:

```text
*.py
*.json
README.md
report/*.md
```

Use an approved secrets-management mechanism.

For development, environment variables may be acceptable:

```text
THREAT_FEED_API_KEY
```

For enterprise deployments, use the organization's approved secrets manager.

---

# 22. Logging Recommendations

The current logging implementation is suitable for the laboratory.

For a higher-level deployment, add:

* Pipeline execution ID.
* Feed ID.
* Feed version.
* Indicator ID.
* Source.
* Decision.
* Policy version.
* Operator/service identity.
* Target firewall.
* Execution result.
* Timestamp.
* Change/approval reference.

Example:

```text
execution_id
feed_id
indicator_id
policy_version
target
decision
execution_mode
change_reference
result
timestamp
```

Do not log secrets or credentials.

---

# 23. Reporting Recommendations

Reports should distinguish:

```text
Received
Validated
Rejected
Monitored
Ignored
Block Proposed
Block Applied
Block Failed
Expired
```

This prevents ambiguity between:

```text
BLOCK proposed
```

and:

```text
BLOCK actually applied
```

The current Day 24 implementation correctly reports firewall modification as `NONE` during dry-run execution.

---

# 24. Rate Limiting and Blast-Radius Protection

A production implementation should protect against a malicious or corrupted feed causing thousands of firewall changes.

Recommended controls:

```text
Maximum Indicators / Run
Maximum Block Proposals / Run
Maximum Changes / Hour
Maximum Changes / Day
```

Example conceptual flow:

```text
Feed
 |
 v
5000 indicators
 |
 v
Policy
 |
 v
1500 BLOCK decisions
 |
 v
Safety Limit
 |
 v
Reject / Queue / Require Approval
```

This is especially important for automated security controls.

---

# 25. Approval Workflow

For high-impact environments, consider introducing an approval queue:

```text
Threat Intelligence
        |
        v
Validation
        |
        v
Policy
        |
        v
Block Proposal
        |
        v
Human / Change Approval
        |
        v
Firewall Backend
```

This is preferable to allowing an external feed to directly modify a production perimeter.

CIS guidance emphasizes documented network-device configurations and documented reasons and ownership for traffic rules.

---

# 26. Rollback

Every production rule should have a rollback path.

Recommended rule lifecycle:

```text
PROPOSED
   |
   v
APPROVED
   |
   v
APPLIED
   |
   +----> EXPIRED
   |
   +----> REMOVED
   |
   +----> ROLLED BACK
```

The system should be able to identify exactly which automation run created a rule.

---

# 27. Testing Recommendations

Before introducing another authorized target or production firewall backend, maintain the existing tests and add:

### Unit Tests

Test:

* Target validation.
* Scope validation.
* Feed authentication.
* Schema validation.
* Expiration.
* Deduplication.
* Policy thresholds.
* Rule generation.

### Integration Tests

Test:

```text
Feed → Validation → Policy → Adapter
```

against a controlled test environment.

### Failure Tests

Test:

* Invalid feed.
* Invalid IP.
* Invalid risk score.
* Missing fields.
* Expired indicators.
* Duplicate indicators.
* Unauthorized target.
* Firewall API failure.
* Timeout.
* Authentication failure.

### Regression Test

The full suite must remain green:

```bash
python3 -m pytest -q
```

Do not deploy a new backend merely because one integration test succeeds.

---

# 28. Recommended Test Environment

For professional development, use a dedicated isolated environment.

Recommended topology:

```text
             Test Network
                  |
        +---------+---------+
        |                   |
        v                   v
 Threat Intel Test     Firewall Test
    Service              Backend
        |                   |
        +---------+---------+
                  |
                  v
             Day 24 Tool
```

Use:

* Virtual machines.
* Containers.
* Dedicated lab VLAN.
* Disposable firewall instance.
* Synthetic threat feeds.

Do not initially test an experimental production firewall adapter against a production perimeter.

---

# 29. Target Change Checklist

When moving from the default laboratory environment to another **authorized** environment, review these areas.

### Step 1 — Authorization

Confirm:

```text
[ ] Target is explicitly authorized
[ ] Testing window is approved
[ ] Firewall owner is identified
[ ] Change ticket exists
[ ] Rollback procedure exists
```

### Step 2 — Feed

Confirm:

```text
[ ] Feed source is approved
[ ] Authentication is configured
[ ] TLS is verified
[ ] Feed schema is documented
[ ] Feed freshness is validated
```

### Step 3 — Scope

Confirm:

```text
[ ] Target is explicitly allowlisted
[ ] Network ranges are correct
[ ] DNS resolution is controlled
[ ] No unintended destinations are permitted
```

### Step 4 — Policy

Review:

```text
[ ] Block threshold
[ ] Monitor threshold
[ ] Allowlist behavior
[ ] Indicator expiration
[ ] Maximum block count
```

### Step 5 — Firewall

Confirm:

```text
[ ] DRY-RUN tested
[ ] Backend isolated behind adapter
[ ] Authentication configured
[ ] Rollback tested
[ ] Audit logging enabled
```

### Step 6 — Testing

Run:

```bash
python3 -m pytest -q
```

Then perform controlled integration testing.

### Step 7 — Deployment

Only after all controls pass should an authorized production backend be considered.

---

# 30. Files That Should Usually NOT Be Changed

When adapting the project to another authorized environment, avoid unnecessary modifications to:

```text
scanner/models.py
scanner/policies.py
scanner/validation.py
tests/test_models.py
tests/test_policies.py
tests/test_validation.py
```

These represent core domain and security logic.

If a production requirement requires changes to these files, add tests first and document the security reason for the change.

---

# 31. Files Most Likely to Change

For a new environment, the normal change points should be:

```text
scanner/config.py
scanner/ingestion.py
scanner/firewall.py
scanner/reporting.py
scanner/validation_pipeline.py
input/*.json
tests/
authorized-target-guide.md
```

For a high-quality architecture, prefer adding new modules rather than continually modifying existing core components.

For example:

```text
scanner/
├── feeds/
├── firewall/
├── scope.py
├── validation.py
├── policies.py
└── reporting.py
```

This keeps provider-specific and environment-specific logic isolated.

---

# 32. Recommended Production Architecture

A mature implementation should evolve toward:

```text
                 Approved Threat Feed
                         |
                         v
                 Secure Feed Adapter
                         |
                         v
                Authentication /
                 Integrity Check
                         |
                         v
                  Schema Validation
                         |
                         v
                 Record Validation
                         |
                         v
                Deduplication /
                   Enrichment
                         |
                         v
                 Scope Validation
                         |
                         v
                  Policy Engine
                         |
                         v
                  Safety Limits
                         |
                         v
                 Approval Queue
                         |
                         v
                 Firewall Adapter
                         |
                +--------+--------+
                |                 |
                v                 v
             DRY-RUN          Approved Backend
                                  |
                                  v
                         Controlled Firewall
                                  |
                                  v
                          Audit / Monitoring
```

This architecture keeps external intelligence, decision-making, and enforcement logically separated.

---

# 33. Professional-Level Code Improvements

For a high-quality production-oriented implementation, prioritize the following improvements.

## Priority 1 — Explicit Target Scope

Add:

```text
scanner/scope.py
```

and require all externally supplied targets to pass authorization checks.

---

## Priority 2 — Firewall Backend Interface

Separate:

```text
FirewallAdapter
```

from the actual vendor implementation.

Recommended:

```text
FirewallBackend
├── DryRunBackend
└── ApprovedFirewallBackend
```

---

## Priority 3 — Feed Adapter Interface

Separate external feed communication from parsing:

```text
ThreatFeedProvider
├── MockFeedProvider
└── ApprovedFeedProvider
```

---

## Priority 4 — Indicator Lifecycle

Add:

```text
first_seen
last_seen
expires_at
confidence
```

and implement expiration.

---

## Priority 5 — Deduplication

Normalize and deduplicate indicators before policy evaluation.

---

## Priority 6 — Safety Limits

Add maximum:

```text
Indicators/run
Blocks/run
Changes/hour
Changes/day
```

---

## Priority 7 — Stronger Audit Records

Add:

```text
execution_id
policy_version
feed_version
change_reference
operator/service_identity
target_firewall
```

---

## Priority 8 — Approval Workflow

Require explicit approval before production firewall changes.

---

## Priority 9 — Rollback

Every applied rule should have a deterministic rollback or expiration mechanism.

---

## Priority 10 — Security Automation

Add CI checks such as:

```text
pytest
ruff
mypy
bandit
pip-audit
```

where appropriate for the project.

The goal should be:

```text
Tests
+
Static Analysis
+
Dependency Audit
+
Security Review
+
Controlled Integration Test
```

rather than relying solely on unit tests.

---

# 34. Recommended Git Workflow

When changing the target/environment implementation:

1. Create a dedicated branch.
2. Make one logical change at a time.
3. Add tests with each security-sensitive change.
4. Run the complete test suite.
5. Review the Git diff.
6. Document authorization.
7. Perform controlled integration testing.
8. Obtain required approval.
9. Merge only after validation.

Avoid:

```bash
git add .
```

when the repository contains unrelated files or backup directories.

Stage only the intended project files.

---

# 35. Production Deployment Rule

The following rule should be treated as mandatory:

> **No external target or production firewall should be used merely because the tool can technically reach it.**

Technical reachability is not authorization.

The target must be explicitly within the approved scope.

---

# 36. Security Recommendations Summary

For a professional deployment:

```text
1. Explicit authorization
2. Target allowlisting
3. Secure feed authentication
4. Schema validation
5. Record validation
6. Feed integrity verification
7. Indicator expiration
8. Deduplication
9. Source confidence
10. Risk-based policy
11. Safety limits
12. DRY-RUN by default
13. Approval workflow
14. Isolated firewall adapter
15. Rollback capability
16. Comprehensive audit logging
17. Continuous testing
18. Change management
```

OWASP's guidance supports explicit trusted-destination allowlisting and strong input validation for systems that interact with network destinations.

CIS guidance similarly emphasizes maintaining standard network-device configurations, documenting traffic rules and their business justification, and using automated mechanisms to detect configuration changes.

---

# 37. Final Authorization Checklist

Before using Day 24 with any environment other than the controlled laboratory:

```text
AUTHORIZATION
[ ] Written authorization obtained
[ ] Target scope documented
[ ] Testing window approved
[ ] Owner/contact identified

FEED
[ ] Feed source approved
[ ] Authentication configured
[ ] Integrity verified
[ ] Schema validated
[ ] Freshness checked

SCOPE
[ ] Target explicitly allowlisted
[ ] Network ranges verified
[ ] DNS behavior reviewed
[ ] No unintended targets permitted

POLICY
[ ] Risk thresholds reviewed
[ ] Allowlist reviewed
[ ] Expiration configured
[ ] Safety limits configured

FIREWALL
[ ] DRY-RUN completed
[ ] Backend tested separately
[ ] Rollback tested
[ ] Audit logging enabled
[ ] Production change approved

TESTING
[ ] Unit tests pass
[ ] Integration tests pass
[ ] Failure tests pass
[ ] Full regression suite passes

DEPLOYMENT
[ ] Change ticket approved
[ ] Monitoring active
[ ] Emergency rollback available
[ ] Post-change validation planned
```

---

# 38. Final Recommendation

The current Day 24 implementation should remain a **DRY-RUN laboratory by default**.

If the project is later developed into a professional threat-intelligence enforcement platform, the recommended progression is:

```text
Current Lab
    |
    v
Stronger Validation
    |
    v
Explicit Scope Control
    |
    v
Feed Authentication
    |
    v
Dedicated Provider Adapter
    |
    v
Dedicated Firewall Backend
    |
    v
Isolated Integration Environment
    |
    v
Approval + Change Management
    |
    v
Controlled Production Deployment
```

Do not skip directly from the current mock fixture to a production firewall.

The strongest architecture is one where **untrusted intelligence never directly controls security infrastructure**. Every transition should pass through explicit validation, authorization, policy, safety controls, and auditability.

---

## Document Status

**Project:** Day 24 — Automated Threat Intelligence IP Blocking Pipeline

**Default Mode:** `DRY-RUN`

**Default Data:** Controlled mock threat-intelligence fixtures

**Production Firewall Modification:** Not enabled

**External Target Use:** Requires explicit authorization

**Recommended Deployment Model:** Isolated, validated, approved, auditable integration