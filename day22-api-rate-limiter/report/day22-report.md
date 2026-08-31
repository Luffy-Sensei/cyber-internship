# Day 22 — API Rate Limiting with Token Bucket Logic

## 1. Executive Summary

Day 22 implements a stateful API rate-limiting component based on the **Token Bucket algorithm**.

The objective was to demonstrate how a defensive application-layer control can restrict excessive request volume while allowing legitimate traffic to proceed. The implementation was expanded beyond the minimal assignment example into a modular, testable component with configuration validation, per-client state isolation, structured request decisions, deterministic execution validation, logging, and machine-readable evidence reporting.

The completed implementation demonstrates:

* Configurable token-bucket capacity.
* Configurable token refill rate.
* Independent request state for individual clients.
* Token consumption on permitted requests.
* Automatic denial after token exhaustion.
* Gradual token replenishment.
* Capacity ceiling enforcement.
* Fractional token accounting.
* Structured `ALLOW` / `DENY` decisions.
* Retry timing for denied requests.
* Configuration validation.
* Deterministic execution validation.
* JSON evidence generation.
* Operational logging.
* Automated unit-test coverage.

The final validation execution completed successfully with:

| Metric                    |    Result |
| ------------------------- | --------: |
| Validation requests       |         7 |
| Allowed                   |         5 |
| Denied                    |         2 |
| Denial rate               |    28.57% |
| Clients tested            |         2 |
| Refill verified           |      True |
| Client isolation verified |      True |
| Automated tests           | 39 passed |
| `git diff --check`        |     Clean |

---

## 2. Objective

The objective of this laboratory was to construct a stateful rate-tracking mechanism capable of protecting API/application endpoints from excessive automated request activity.

The primary mechanism is a Token Bucket:

```text
                 Token Bucket
              ┌─────────────────┐
              │ Capacity        │
              │ Refill Rate     │
              │ Current Tokens  │
              │ Last Updated    │
              └────────┬────────┘
                       │
                 Request Arrives
                       │
             ┌─────────▼─────────┐
             │ Replenish Tokens  │
             │ according to      │
             │ elapsed time      │
             └─────────┬─────────┘
                       │
                Tokens >= 1 ?
                  /          \
                YES           NO
                 │             │
              ALLOW          DENY
                 │             │
          consume 1 token   retry_after
```

The implementation treats each client as an independent rate-limiting identity.

---

## 3. Security Context

Unrestricted API endpoints can be subjected to high-volume automated traffic.

Examples include:

* Automated credential testing.
* Excessive API polling.
* Resource exhaustion.
* Request floods.
* Accidental client retry storms.
* Abusive automation.
* Excessive consumption of expensive application operations.

Rate limiting does not replace authentication, authorization, WAF controls, input validation, or application-level security controls. Instead, it provides an additional availability and abuse-resistance layer.

A Token Bucket is particularly useful because it permits controlled bursts while maintaining a defined long-term request rate.

---

# 4. Architecture

The Day 22 implementation was deliberately separated into multiple layers.

```text
scanner/
├── models.py
├── config.py
├── limiter.py
├── policies.py
├── engine.py
└── validation.py
```

### Component responsibilities

#### `scanner/models.py`

Defines structured data models used by the rate-limiting system.

Responsibilities include representing:

* Client state.
* Rate-limit configuration.
* Request decisions.
* Validation-related data.

---

#### `scanner/config.py`

Provides configuration handling and validation.

The configuration layer ensures that invalid operational parameters are rejected before the limiter is used.

Examples of configuration constraints include:

* Positive token capacity.
* Valid refill rate.
* Valid policy configuration.
* Consistent numerical parameters.

---

#### `scanner/limiter.py`

Contains the core Token Bucket state-management implementation.

The limiter maintains state for each client independently.

Conceptually:

```text
client-A
    ├── capacity
    ├── tokens
    └── last_updated

client-B
    ├── capacity
    ├── tokens
    └── last_updated

client-C
    ├── capacity
    ├── tokens
    └── last_updated
```

This prevents activity from one client from consuming another client's allowance.

---

#### `scanner/policies.py`

Defines reusable rate-limiting policies.

Policies allow the limiter configuration to be expressed as named operational profiles rather than embedding numerical values throughout the application.

This creates a cleaner separation between:

```text
Policy
   ↓
Configuration
   ↓
Rate Limiter
```

---

#### `scanner/engine.py`

Provides the decision-oriented interface around the underlying limiter.

Rather than exposing only:

```python
True
```

the engine can provide structured information describing the request decision.

Conceptually:

```text
ALLOW
client = client-A
remaining_tokens = 2.0
```

or:

```text
DENY
client = client-A
remaining_tokens = 0.0
retry_after = 2.0
```

This makes the component more useful for API gateways, logging, monitoring, and reporting.

---

#### `scanner/validation.py`

Provides deterministic execution validation.

The validation layer executes a controlled request sequence and verifies:

* Initial allowance.
* Token consumption.
* Denial after exhaustion.
* Refill behavior.
* Multiple-client isolation.
* Final aggregate results.
* Evidence generation.
* Operational logging.

---

# 5. Token Bucket Algorithm

The Token Bucket algorithm maintains a numerical token balance.

For each client:

```text
tokens = current token balance
capacity = maximum token balance
refill_rate = tokens regenerated per second
elapsed = time since previous update
```

The refill calculation is conceptually:

```text
new_tokens =
    min(
        capacity,
        old_tokens + elapsed × refill_rate
    )
```

If at least one token is available:

```text
tokens >= 1
```

the request is permitted and one token is consumed.

If insufficient tokens remain:

```text
tokens < 1
```

the request is denied.

This gives the implementation two important properties:

1. **Burst control** — clients may consume their available token allocation quickly.
2. **Long-term rate control** — tokens return gradually rather than becoming permanently exhausted.

---

# 6. Example Policy

The primary validation policy used:

```text
Capacity:       3 tokens
Refill rate:    0.5 tokens/second
```

This means a client initially receives three tokens.

At the configured refill rate, one token becomes available approximately every two seconds once the bucket has been exhausted.

The effective validation sequence demonstrated:

```text
Request 01 → ALLOW
Request 02 → ALLOW
Request 03 → ALLOW
Request 04 → DENY
Request 05 → DENY
Request 06 → ALLOW
```

The final request becomes possible after controlled token replenishment.

---

# 7. Decision Intelligence

The implementation was intentionally designed to provide more information than a Boolean result.

A permitted request exposes information such as:

```text
decision = ALLOWED
remaining_tokens = 2.000
retry_after = 0
```

A denied request can expose:

```text
decision = DENIED
remaining_tokens = 0.000
retry_after = 2.000
```

This information can be consumed by higher-level infrastructure.

For example, an API gateway could translate a denied decision into:

```text
HTTP 429 Too Many Requests
```

and potentially provide an appropriate retry indication.

---

# 8. Multi-Client Isolation

A critical property of the implementation is independent client state.

The validation sequence included:

```text
client-A → requests 1–6
client-B → request 7
```

The resulting evidence showed:

```text
client-A
    Request 1 → ALLOWED
    Request 2 → ALLOWED
    Request 3 → ALLOWED
    Request 4 → DENIED
    Request 5 → DENIED
    Request 6 → ALLOWED

client-B
    Request 7 → ALLOWED
```

The successful request from `client-B` demonstrates that exhaustion of `client-A`'s bucket does not consume the second client's allowance.

This is an important architectural property for client-aware API rate limiting.

---

# 9. Validation Execution

The final validation was executed with:

```bash
python3 -m scanner.validation --verbose
```

The execution reported:

```text
DAY 22 - API RATE-LIMITING VALIDATION

Policy             : default
Requests           : 7
Allowed            : 5
Denied             : 2
Denial rate        : 28.57%
Clients tested     : 2
Refill verified    : True
Isolation verified : True
```

The detailed request sequence was also recorded:

```text
Request sequence=1 client=client-A decision=ALLOWED
Request sequence=2 client=client-A decision=ALLOWED
Request sequence=3 client=client-A decision=ALLOWED
Request sequence=4 client=client-A decision=DENIED
Request sequence=5 client=client-A decision=DENIED
Request sequence=6 client=client-A decision=ALLOWED
Request sequence=7 client=client-B decision=ALLOWED
```

This provides execution evidence that the limiter is not merely passing unit tests but is performing the expected state transitions.

---

# 10. Automated Testing

The final automated test suite contains:

```text
39 passed
```

Executed with:

```bash
python3 -m pytest -q
```

Final result:

```text
39 passed in 0.15s
```

The test suite covers the major implementation layers.

### Configuration tests

Validate:

* Valid configuration.
* Invalid configuration.
* Policy construction.
* Configuration constraints.

### Model tests

Validate:

* Structured state representation.
* Request decision representation.
* Model defaults and invariants.

### Limiter tests

Validate:

* Initial allowance.
* Token consumption.
* Exhaustion.
* Denial.
* Refill.
* Capacity ceiling.
* Multiple clients.
* Fractional token behavior.

### Policy tests

Validate:

* Available policies.
* Policy parameters.
* Policy consistency.

### Engine tests

Validate:

* Structured decisions.
* Allowed requests.
* Denied requests.
* Remaining token calculations.
* Retry timing.

### Validation tests

Validate:

* Deterministic request sequences.
* Aggregate counts.
* Refill verification.
* Isolation verification.
* Validation report generation.
* Logging behavior.

---

# 11. Operational Logging

The validation runner writes operational information to:

```text
output/logs/day22_validation.log
```

The log records:

* Validation startup.
* Selected policy.
* Capacity.
* Refill rate.
* Individual request decisions.
* Remaining tokens.
* Retry timing.
* Final request totals.
* Report-generation status.

Example:

```text
INFO | day22 | Starting validation policy=default capacity=3.0 refill_rate=0.5
INFO | day22 | Request sequence=1 client=client-A decision=ALLOWED
INFO | day22 | Request sequence=4 client=client-A decision=DENIED
INFO | day22 | Request sequence=6 client=client-A decision=ALLOWED
INFO | day22 | Request sequence=7 client=client-B decision=ALLOWED
INFO | day22 | Validation complete requests=7 allowed=5 denied=2
```

The same information is intentionally visible during `--verbose` execution.

This is useful during laboratory validation because the operator can observe the state transitions immediately while a persistent log provides post-execution evidence.

---

# 12. Evidence Report

The validation runner produces:

```text
output/reports/day22_rate_limit_validation.json
```

The report captures structured validation information such as:

* Execution configuration.
* Policy used.
* Requests attempted.
* Allowed requests.
* Denied requests.
* Denial rate.
* Clients tested.
* Refill verification.
* Client-isolation verification.
* Validation status.
* Individual request decisions.

JSON was selected because it can be consumed by:

* CI/CD systems.
* Monitoring pipelines.
* Security dashboards.
* Automated assessment tooling.
* Future reporting components.

---

# 13. Final Project Structure

The completed Day 22 laboratory follows this structure:

```text
day22-api-rate-limiter/
├── input/
├── output/
│   ├── logs/
│   │   └── day22_validation.log
│   └── reports/
│       └── day22_rate_limit_validation.json
├── README.md
├── report/
│   └── day22-report.md
├── requirements.txt
├── scanner/
│   ├── __init__.py
│   ├── config.py
│   ├── engine.py
│   ├── limiter.py
│   ├── models.py
│   ├── policies.py
│   └── validation.py
├── screenshots/
└── tests/
    ├── test_config.py
    ├── test_engine.py
    ├── test_limiter.py
    ├── test_models.py
    ├── test_policies.py
    └── test_validation.py
```

---

# 14. Enterprise Integration Model

A production deployment can place rate limiting at the edge of an application architecture.

```text
                         INTERNET
                             │
                             ▼
                  ┌─────────────────────┐
                  │      WAF / LB       │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │    API Gateway      │
                  │                     │
                  │  Rate-Limit Engine  │
                  └──────────┬──────────┘
                             │
                       ┌─────┴─────┐
                       │           │
                    ALLOW         DENY
                       │           │
                       ▼           ▼
                ┌────────────┐   HTTP 429
                │ Application │
                │   Tier      │
                └──────┬─────┘
                       │
                       ▼
                ┌────────────┐
                │ Database / │
                │ Services   │
                └────────────┘
```

In a distributed environment, the conceptual bucket state may be stored in a shared low-latency datastore rather than process-local memory.

Possible production components include:

* API gateways.
* Load balancers.
* Distributed caches.
* Service meshes.
* WAF infrastructure.
* Centralized observability systems.

The laboratory implementation intentionally keeps the state local and deterministic so that algorithm behavior can be tested without introducing infrastructure dependencies.

---

# 15. Production Considerations

A production-grade implementation would require additional considerations beyond this laboratory.

### Distributed state

Multiple API gateway instances require a shared or coordinated rate-limit state if clients must receive consistent limits across instances.

### Identity selection

The limiter should carefully define the rate-limit identity.

Possible identities include:

```text
Client IP
Authenticated user
API key
Tenant
Application ID
Endpoint + client
```

Blindly relying on IP addresses can produce inaccurate results in environments using NAT, proxies, or shared networks.

### Trusted proxy configuration

If client IP information is extracted from forwarding headers, the application must distinguish trusted proxy infrastructure from untrusted client-controlled headers.

### Endpoint-specific policies

Different API operations may require different limits.

For example:

```text
Normal API endpoint → higher allowance
Expensive search endpoint → lower allowance
Authentication endpoint → strict protection
```

### Observability

Production systems should monitor:

* Request volume.
* Denial rates.
* Top rate-limited identities.
* Endpoint-level throttling.
* Retry behavior.
* Gateway latency.
* Bucket-store health.

### Failure handling

Distributed rate-limit infrastructure should define what happens if the shared state backend becomes unavailable.

Possible strategies include controlled fail-open or fail-closed behavior depending on the risk profile of the protected service.

---

# 16. Security Limitations

This laboratory demonstrates rate limiting as a defensive control, but it does not represent a complete API security solution.

Rate limiting alone does not prevent:

* Authentication bypass.
* Authorization failures.
* Injection vulnerabilities.
* Session compromise.
* Credential theft.
* Application-layer logic flaws.
* Distributed abuse using many independent identities.

It should therefore be considered one component of a broader defense-in-depth architecture.

---

# 17. Validation Integrity

The implementation was validated using both automated tests and deterministic execution evidence.

Final verification:

```bash
python3 -m pytest -q
```

Result:

```text
39 passed
```

Repository formatting verification:

```bash
git diff --check
```

Result:

```text
clean
```

Execution validation:

```bash
python3 -m scanner.validation --verbose
```

Result:

```text
Requests           : 7
Allowed            : 5
Denied             : 2
Denial rate        : 28.57%
Clients tested     : 2
Refill verified    : True
Isolation verified : True
```

These three validation layers provide complementary evidence:

```text
Unit Tests
    │
    ├── Component correctness
    │
    ▼
Deterministic Execution
    │
    ├── Runtime behavior
    │
    ▼
JSON + Log Evidence
    │
    └── Auditable execution record
```

---

# 18. Conclusion

Day 22 successfully implements a modular Token Bucket rate-limiting component and validates its behavior through automated tests and deterministic runtime evidence.

The implementation progresses from the basic assignment concept:

```python
allow_request(client_ip)
```

to a more maintainable defensive architecture containing:

```text
Configuration
     ↓
Policy
     ↓
Token Bucket
     ↓
Decision Engine
     ↓
Validation Runner
     ↓
JSON / Log Evidence
```

The final validation demonstrated that the system can:

* Permit requests while tokens are available.
* Deny requests after bucket exhaustion.
* Replenish tokens according to elapsed time.
* Respect the configured capacity ceiling.
* Maintain independent state between clients.
* Produce structured decisions.
* Generate persistent operational evidence.

**Final Day 22 status: VALIDATED — PASS**

```text
39 automated tests passed
7 validation requests executed
5 requests allowed
2 requests denied
Refill behavior verified
Client isolation verified
Logging verified
JSON evidence generated
```

The resulting implementation provides a solid foundation for understanding how stateful rate-limiting controls can be integrated into larger API gateway and distributed application architectures.