# Day 22 — API Rate-Limiting Token Bucket

A defensive Python implementation of **stateful API rate limiting using the Token Bucket algorithm**.

This lab demonstrates how applications and API gateways can control request volume per client, reject requests after token exhaustion, replenish capacity over time, and produce structured decision data suitable for logging, validation, and gateway integration.

> **Security Notice:** This project is a defensive training component. It is intended for authorized development, testing, and security-lab environments.

---

## 1. Objective

Implement a stateful rate-limiting mechanism that protects application endpoints from excessive automated requests and resource exhaustion.

The implementation extends the basic Token Bucket assignment into a modular defensive component with:

* Per-client token accounting
* Configurable bucket capacity
* Configurable refill rate
* Stateful request decisions
* Structured ALLOW/DENY results
* Retry-after calculation
* Client isolation
* Configuration validation
* Deterministic execution validation
* JSON evidence reporting
* Operational logging
* Automated test coverage

---

## 2. Architecture

The project is organized into separate layers so that rate-limiting logic can be tested independently from execution and reporting.

```text
scanner/
├── __init__.py
├── models.py
├── config.py
├── limiter.py
├── policies.py
├── engine.py
└── validation.py

tests/
├── test_models.py
├── test_config.py
├── test_limiter.py
├── test_policies.py
├── test_engine.py
└── test_validation.py

input/
output/
├── logs/
└── reports/

report/
└── day22-report.md

screenshots/
requirements.txt
README.md
```

### Component responsibilities

| Component         | Responsibility                                       |
| ----------------- | ---------------------------------------------------- |
| `models.py`       | Structured configuration and decision models         |
| `config.py`       | Validation and construction of limiter configuration |
| `limiter.py`      | Core Token Bucket accounting                         |
| `policies.py`     | Named rate-limiting policy definitions               |
| `engine.py`       | Request evaluation and structured decisions          |
| `validation.py`   | Deterministic execution and evidence generation      |
| `tests/`          | Unit and behavioral verification                     |
| `output/logs/`    | Persistent operational execution logs                |
| `output/reports/` | Machine-readable validation evidence                 |
| `report/`         | Technical analysis and architecture documentation    |

---

## 3. Token Bucket Model

The implementation follows the Token Bucket model.

```text
                 ┌─────────────────────────┐
                 │       Token Bucket       │
                 │                         │
                 │ Capacity                │
                 │ Refill Rate             │
                 │ Current Tokens          │
                 │ Last Updated            │
                 └────────────┬────────────┘
                              │
                       Incoming Request
                              │
                              ▼
                     Tokens Available?
                       /            \
                     YES             NO
                      │               │
                      ▼               ▼
                    ALLOW           DENY
                      │               │
                Consume token     Retry-after
```

A bucket has a maximum capacity and replenishes tokens continuously according to the configured refill rate.

For the validation policy used in this lab:

```text
Capacity:       3 tokens
Refill rate:    0.5 tokens/second
```

This means the bucket initially contains three tokens and replenishes at half a token per second until the configured capacity is reached.

---

## 4. Per-Client Isolation

The rate limiter maintains independent state for each client.

```text
Client A ──► Bucket A
Client B ──► Bucket B
Client C ──► Bucket C
```

Exhausting Client A's bucket does not consume Client B's allocation.

This is important for multi-client API environments because one high-volume client should not automatically exhaust the request budget assigned to unrelated clients.

---

## 5. Structured Decisions

The engine does not simply return `True` or `False`.

A request decision contains useful information such as:

```text
Decision:
    ALLOW
    client = client-A
    remaining_tokens = 2.0
```

or:

```text
Decision:
    DENY
    client = client-A
    remaining_tokens = 0.0
    retry_after = 2.0
```

This makes the component more useful for:

* API gateway integration
* HTTP 429 responses
* observability
* security monitoring
* audit logging
* automated validation
* operational dashboards

---

## 6. Validation Execution

The validation runner performs a deterministic request sequence against the configured rate-limiting engine.

Example policy:

```text
Capacity: 3
Refill:   0.5/sec
```

Observed execution:

```text
Request 01 → ALLOWED
Request 02 → ALLOWED
Request 03 → ALLOWED
Request 04 → DENIED
Request 05 → DENIED
Request 06 → ALLOWED
Request 07 → ALLOWED
```

The sequence demonstrates:

1. Initial token availability
2. Token consumption
3. Bucket exhaustion
4. Automated request denial
5. Token replenishment
6. Subsequent request allowance
7. Independent client state

---

## 7. Validation Evidence

The current validation execution produced:

```text
DAY 22 - API RATE-LIMITING VALIDATION

Policy              : default
Requests            : 7
Allowed             : 5
Denied              : 2
Denial rate         : 28.57%
Clients tested      : 2
Refill verified     : True
Isolation verified  : True
```

Per-request logging also records the remaining token count and retry interval.

Example:

```text
Request sequence=3 client=client-A
decision=ALLOWED remaining_tokens=0.000 retry_after=0.000

Request sequence=4 client=client-A
decision=DENIED remaining_tokens=0.000 retry_after=2.000
```

---

## 8. Logging

Operational execution is written to:

```text
output/logs/day22_validation.log
```

Running:

```bash
python3 -m scanner.validation --verbose
```

provides live console visibility while also preserving the execution log for later analysis.

The console output and persistent log serve different purposes:

```text
Validation Engine
       │
       ├──► Console
       │      Live operator feedback
       │
       └──► Log file
              Persistent evidence
```

---

## 9. JSON Reporting

The validation runner generates:

```text
output/reports/day22_rate_limit_validation.json
```

The report captures structured execution information including:

* Policy information
* Rate-limit configuration
* Requests attempted
* Allowed requests
* Denied requests
* Clients tested
* Refill verification
* Isolation verification
* Validation status
* Execution details

The JSON format is intended to support automated processing and future integration with security reporting pipelines.

---

## 10. Testing

The project uses `pytest` for automated verification.

Run the complete test suite:

```bash
python3 -m pytest -q
```

Current validation result:

```text
39 passed
```

The test suite covers:

* Model behavior
* Configuration validation
* Token consumption
* Initial allowance
* Bucket exhaustion
* Refill behavior
* Capacity ceiling
* Multiple clients
* Fractional token behavior
* Policy definitions
* Engine decisions
* Retry-after calculations
* Validation execution
* Logging behavior

---

## 11. Code Quality Verification

Before committing changes, run:

```bash
git diff --check
```

A clean result indicates that Git found no whitespace errors in the current diff.

Recommended final verification:

```bash
python3 -m pytest -q
git diff --check
git status --short
```

---

## 12. Running the Validation Tool

Activate the project environment:

```bash
source .venv/bin/activate
```

Run the validation engine:

```bash
python3 -m scanner.validation
```

For detailed operational logging:

```bash
python3 -m scanner.validation --verbose
```

After execution, inspect the evidence:

```bash
cat output/logs/day22_validation.log
```

and:

```bash
cat output/reports/day22_rate_limit_validation.json
```

---

## 13. Configuration

The default validation policy is defined inside the project's policy/configuration layer.

The conceptual configuration is:

```text
Policy:
    capacity = 3
    refill_rate = 0.5 tokens/sec
```

The rate limiter should be configured according to the requirements of the authorized application or service being protected.

For an actual application integration, configuration should be adjusted through the project's configuration/policy layer rather than modifying the Token Bucket algorithm itself.

---

## 14. Enterprise Gateway Integration

A production architecture can place rate limiting at the application edge.

```text
                         INTERNET
                            │
                            ▼
                 ┌─────────────────────┐
                 │     Edge / WAF / LB  │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │    Rate Limiter     │
                 │                     │
                 │   Token Buckets     │
                 └──────────┬──────────┘
                            │
                   ┌────────┴────────┐
                   │                 │
                 ALLOW              DENY
                   │                 │
                   ▼                 ▼
             ┌───────────┐       HTTP 429
             │  API GW   │
             └─────┬─────┘
                   │
                   ▼
             ┌───────────┐
             │Application│
             │   Tier    │
             └───────────┘
```

In a distributed deployment, the conceptual in-memory bucket state used by this training implementation would normally be replaced or coordinated through a shared state mechanism when multiple gateway instances must enforce a common quota.

Examples of production considerations include:

* Distributed state
* Horizontal scaling
* Consistent client identity
* Proxy-aware identity handling
* Clock behavior
* Configuration distribution
* Observability
* Fail-open versus fail-closed behavior
* HTTP 429 response handling
* Quota policy management

These concerns are architectural considerations rather than requirements for the local training implementation.

---

## 15. Security Considerations

Rate limiting is a defensive control, not a complete application security mechanism.

A production deployment should consider:

### Client identification

Do not blindly trust an attacker-controlled header as the source of client identity.

Where applicable, identity may be derived from authenticated principals, trusted gateway metadata, or carefully validated network information.

### Distributed deployments

An in-memory limiter is local to the process. Multiple application instances require an appropriate shared or coordinated state strategy if a global quota is required.

### Burst behavior

Token Bucket parameters determine how much burst traffic can be tolerated.

Increasing capacity increases the permitted burst size.

Increasing refill rate increases the sustainable request rate.

### HTTP integration

A denied request can be translated by an API gateway or application layer into an appropriate HTTP response such as:

```text
HTTP 429 Too Many Requests
```

A `Retry-After` value can communicate when the client should retry.

### Observability

Production systems should monitor:

* Request volume
* Denial rate
* Top rate-limited clients
* Policy violations
* Retry behavior
* Gateway latency
* Limiter state/storage health

---

## 16. Authorized Target Usage

This repository contains a reusable defensive rate-limiting component rather than a remote attack tool.

For an authorized application integration, the normal workflow is:

```text
Authorized Application
        │
        ▼
Identify protected endpoint
        │
        ▼
Choose appropriate policy
        │
        ▼
Configure capacity/refill rate
        │
        ▼
Integrate rate-limit decision
        │
        ├── ALLOW → process request
        │
        └── DENY  → return appropriate response
```

The core Token Bucket implementation should remain independent from application-specific HTTP handling.

This separation allows the limiter to be tested locally before being integrated into an authorized API gateway or application.

---

## 17. Evidence Layout

After validation, the expected evidence structure is:

```text
output/
├── logs/
│   └── day22_validation.log
└── reports/
    └── day22_rate_limit_validation.json
```

Additional screenshots and documentation are stored separately:

```text
screenshots/
report/
└── day22-report.md
```

---

## 18. Project Status

### Phase 1 — Foundation

**Status: COMPLETE**

Implemented:

* Models
* Configuration
* Token Bucket
* Configuration validation
* Core tests

### Phase 2 — Rate-Limiting Engine

**Status: COMPLETE**

Implemented:

* Policy definitions
* Rate-limit engine
* Structured request decisions
* Client isolation
* Retry-after behavior
* Engine tests

### Phase 3 — Execution Validation

**Status: COMPLETE**

Implemented:

* Deterministic validation runner
* Rapid-request sequence
* Denial verification
* Refill verification
* Client-isolation verification
* Operational logging
* JSON evidence generation

### Phase 4 — Documentation & Evidence

**Status: FINALIZATION**

Remaining release activities:

* Final report verification
* README verification
* Evidence screenshots
* Git working-tree verification
* Commit and repository push

---

## 19. Final Verification

Before considering Day 22 complete:

```bash
python3 -m pytest -q
```

Expected result:

```text
39 passed
```

Then:

```bash
git diff --check
```

Then inspect:

```bash
git status --short
```

Finally verify the evidence:

```bash
cat output/logs/day22_validation.log
cat output/reports/day22_rate_limit_validation.json
```

---

## 20. Learning Outcomes

This lab demonstrates practical understanding of:

* Token Bucket rate limiting
* Stateful request control
* Per-client quota isolation
* Token replenishment
* Burst control
* Request denial
* Retry-after calculation
* Configuration validation
* Structured security decisions
* Deterministic security testing
* Operational logging
* JSON evidence generation
* API gateway integration concepts
* Distributed rate-limiting architecture

---

## Conclusion

Day 22 evolves the basic Token Bucket exercise into a modular defensive component suitable for security engineering training.

The implementation separates:

```text
Configuration
     ↓
Token Accounting
     ↓
Policy
     ↓
Decision Engine
     ↓
Validation
     ↓
Evidence
```

The final validation demonstrates that requests can be allowed, denied after bucket exhaustion, permitted again after controlled replenishment, and isolated across clients.

This provides a practical foundation for understanding how rate limiting can be incorporated into defensive API and gateway architectures.