# SE Chain Simulator

**Version:** 1.0.0
**Project:** Cybersecurity Internship — Day 15
**Phase:** Social Engineering Chain Simulation
**Environment:** Authorized Local Laboratory
**Target:** `127.0.0.1`
**Mode:** Lab / Simulation Only
**Language:** Python 3
**Status:** Complete

---

## 1. Overview

SE Chain Simulator is a defensive cybersecurity training framework that models a controlled social-engineering attack chain inside an explicitly authorized laboratory environment.

The project demonstrates how multiple security-analysis stages can be orchestrated through a single execution engine while maintaining:

- explicit authorization controls
- laboratory-only execution
- modular architecture
- structured execution state
- persistent run history
- deterministic reporting
- security-risk assessment
- defensive incident-response simulation
- automated testing
- structured logging
- CLI-based operation

The simulator does **not** perform real-world social-engineering attacks, credential theft, unauthorized phishing, or unauthorized target interaction.

Instead, potentially offensive stages are represented as controlled simulations and security-awareness analysis.

The primary goal is to demonstrate the engineering principles behind an automated security workflow while maintaining a strict defensive and authorized scope.

---

# 2. Project Objectives

The Day 15 implementation has the following objectives:

1. Build a modular social-engineering chain simulator.
2. Orchestrate multiple security-analysis modules through a central engine.
3. Enforce authorization before simulation execution.
4. Generate synthetic laboratory target profiles.
5. Perform phishing-risk analysis rather than real phishing.
6. Generate security-awareness training material.
7. Simulate defensive incident-response actions.
8. Persist completed simulation state between CLI processes.
9. Generate machine-readable and human-readable reports.
10. Provide structured application logging.
11. Provide automated regression testing.
12. Provide a reproducible command-line workflow.

---

# 3. Security and Authorization Boundary

This project is intentionally designed for authorized cybersecurity training.

## Authorized environment

The current laboratory target is:

```text

127.0.0.1
```
The configured environment is:
```text
target_type = localhost
environment = lab
authorized = true
```
The simulator is designed around an explicit authorization check.

If the configured target is not authorized, execution is blocked rather than continuing with the simulation.

Example defensive behavior:
```text
Simulation blocked: target is not authorized
```
This is an intentional security control.

### 3.1 What the simulator does

The simulator can:

- perform passive/simulated OSINT collection
- create synthetic target profiles
- analyze simulated phishing indicators
- generate security-awareness templates
- create simulated security events
- calculate a simulated risk score
- trigger simulated defensive IR actions
- persist simulation state
- generate JSON reports
- generate text reports
- maintain structured logs

### 3.2 What the simulator does NOT do

The project does not provide functionality for:
- unauthorized target interaction
- real credential harvesting
- real credential theft
- real phishing campaigns
- malicious payload delivery
- persistence on third-party systems
- unauthorized exploitation
- unauthorized reconnaissance
- bypassing authorization controls
- real-world social-engineering operations

All potentially sensitive activity remains within the authorized laboratory simulation boundary.

## 4. Technology Stack
| Component            | Technology                  |
| -------------------- | --------------------------- |
| Programming Language | Python 3                    |
| Testing              | pytest                      |
| Data Format          | JSON                        |
| Reporting            | JSON + plain text           |
| Logging              | Python logging              |
| CLI                  | argparse + interactive menu |
| Persistence          | File-based JSON RunStore    |
| Environment          | Linux / Parrot OS           |
| Isolation            | Python virtual environment  |
| Target               | Localhost laboratory        |
| Architecture         | Modular Python package      |


## 5. Requirements

### 5.1 Operating System

Recommended:
- Linux
- Parrot OS
- Debian
- Ubuntu

The project was developed and tested in a Parrot OS laboratory environment.

### 5.2 Python

Python 3 is required.

Check the installed version:
```bash
python --version
```
or:
```bash
python3 --version
```

Python 3.13 was used during development/testing.

### 5.3 Python Virtual Environment

Using a virtual environment is recommended.

Create one:
```bash
python3 -m venv .venv
```
Activate it:
```bash
source .venv/bin/activate
```
The terminal should show something similar to:
```text
(.venv)
```
5.4 Dependencies

Install project dependencies using:
```bash
pip install -r requirements.txt
```
For development/testing:
```bash
pip install pytest
```
Verify pytest:
```bash
pytest --version
```
## 6. Project Structure

The project is organized into modular components.
```text
day15-se-chain/
│
├── se_chain.py
├── README.md
├── requirements.txt
│
├── se_chain/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── engine.py
│   ├── exceptions.py
│   ├── logger.py
│   ├── models.py
│   ├── run_store.py
│   │
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── osint.py
│   │   ├── profile.py
│   │   ├── phish.py
│   │   ├── template.py
│   │   └── ir.py
│   │
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── json_report.py
│   │   └── text_report.py
│   │
│   └── safety/
│       ├── __init__.py
│       ├── authorization.py
│       └── policy.py
│
├── tests/
│
└── output/
    ├── logs/
    ├── runs/
    └── reports/
```
## 7. Architecture

The application follows a modular pipeline architecture.
```text
                         ┌─────────────────────┐
                         │     CLI / User      │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │    Chain Engine     │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
        ┌──────────┐          ┌──────────┐          ┌──────────┐
        │  OSINT   │          │ Profile  │          │  Phish   │
        └────┬─────┘          └────┬─────┘          └────┬─────┘
             │                     │                     │
             └─────────────────────┼─────────────────────┘
                                   │
                                   ▼
                            ┌────────────┐
                            │  Template  │
                            └─────┬──────┘
                                  │
                                  ▼
                            ┌────────────┐
                            │ Defensive  │
                            │     IR     │
                            └─────┬──────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
              ┌───────────┐               ┌───────────┐
              │ RunStore  │               │ Reporting │
              └─────┬─────┘               └─────┬─────┘
                    │                             │
                    ▼                       ┌─────┴─────┐
             output/runs/                  ▼           ▼
                                      JSON Report   Text Report
```
## 8. Core Components
### 8.1 CLI

File:
```text
se_chain/cli.py
```
Responsible for:
- argument parsing
- interactive menu
- simulation execution
- status display
- report generation
- runtime context handling
- persistent state recovery

Supported command-line options:
```bash
python se_chain.py --help
```
## 9. Chain Engine

File:
```text
se_chain/engine.py
```
The ChainEngine is responsible for orchestrating the simulation modules.

The engine coordinates the execution flow rather than implementing individual module logic.

Conceptually:
```text
Authorization
      ↓
OSINT
      ↓
Profile
      ↓
Phish Analysis
      ↓
Security Awareness Template
      ↓
Defensive IR
      ↓
Completion
```
Each stage reports its execution result back to the shared ChainContext.

## 10. Module System

The project uses independent modules so that individual security-analysis stages can be tested and maintained separately.

### 10.1 OSINT Module

File:
```text
se_chain/modules/osint.py
```
Purpose:

- perform controlled passive information collection
- record provider results
- record provider warnings
- return structured module data

The module can complete successfully even when a non-critical external provider generates a warning.

Example:
```text
osint completed with 1 warning(s)
```
A provider warning is therefore not automatically treated as a chain failure.

## 11. Profile Module

File:
```text
se_chain/modules/profile.py
```
Purpose:

Create a synthetic laboratory target profile.

Example result:
```text
Synthetic laboratory target profile created
```
The profile is used as controlled input for subsequent simulation stages.

## 12. Phishing Risk Analysis

File:
```text
se_chain/modules/phish.py
```
The phishing module performs analysis of simulated phishing indicators.

It does not send phishing messages.

The module produces a risk assessment.

Example:
```text
Risk score : 40
Risk level : MEDIUM
```
Risk output can be consumed by the defensive IR stage.

## 13. Security-Awareness Template

File:
```text
se_chain/modules/template.py
```
This stage generates security-awareness training content based on the simulated scenario.

The objective is educational and defensive.

The generated material can be used to demonstrate:

- phishing warning signs
- user awareness
- defensive recommendations
- safe response behavior
## 14. Defensive Incident Response

File:
```text
se_chain/modules/ir.py
```
The IR module simulates defensive actions based on the calculated risk.

Examples of simulated actions can include:

- alert generation
- incident classification
- containment simulation
- investigation simulation
- user/security notification simulation

The actions are recorded in the ChainContext.

Example execution:
```text
Events generated : 10
IR actions       : 5
```
These are simulation artifacts rather than real defensive changes to an external system.

## 15. Safety Architecture

Safety-related logic is separated from the operational modules.
```text
se_chain/safety/
├── authorization.py
└── policy.py
```
This separation allows authorization and execution policy to remain independent from individual simulation stages.

The engine checks whether the configured target is authorized before continuing.

This prevents accidental execution against an unauthorized target.

## 16. Data Model

File:
```text
se_chain/models.py
```
The application uses structured data models for simulation state.

Important concepts include:

### ChainContext

The central runtime object containing:

- run metadata
- authorization state
- target configuration
- module results
- generated events
- IR actions
- simulation data
- errors

### RunMetadata

Contains information such as:

- run ID
- target
- mode
- status
- start time
- completion time
- application
- version

### ModuleResult

Represents the result of an individual module.

It contains:

- module name
- success state
- status
- message
- data
- warnings
- errors
- timestamps

### SimulationEvent

Represents a generated simulation event.

### IRAction

Represents a simulated defensive response action.

## 17. Persistent Run State

File:
```text
se_chain/run_store.py
```
The RunStore solves an important CLI problem:

Python global variables do not survive between separate processes.

For example:
```bash
python se_chain.py --run-all
```
and later:
```bash
python se_chain.py
```
are separate Python processes.

Therefore, the latest context is persisted to:
```text
output/runs/
```
Each run is stored using its unique run ID:
```text
output/runs/<run_id>.json
```
Example:
```text
output/runs/20260823-141824-e47ada4f.json
```
## 18. Run Persistence Workflow

When a simulation completes:
```text
ChainContext
     │
     ▼
RunStore.save()
     │
     ▼
JSON serialization
     │
     ▼
Temporary file
     │
     ▼
Atomic replace
     │
     ▼
output/runs/<run_id>.json
```

When the CLI starts later:
```text
CLI
 │
 ▼
RunStore.load_latest()
 │
 ▼
Latest JSON state
 │
 ▼
ChainContext reconstruction
 │
 ▼
Status / Report
```
This allows simulation state to survive process termination.

## 19. Atomic Persistence

Run state is written using a temporary file followed by replacement.

Conceptually:
```text
simulation.json.tmp
        │
        ▼
atomic replace
        │
        ▼
simulation.json
```
This reduces the risk of leaving a partially written run-state file if a write operation is interrupted.

## 20. Logging

Application logs are stored in:
```text
output/logs/se_chain.log
```
The logging system records structured information including:

- timestamp
- log level
- run ID
- module
- message

Example:
```text
2026-08-23 14:18:24 | INFO | run=20260823-141824-e47ada4f | module=engine | Chain execution started
```
Log levels include:
```text
INFO
WARNING
ERROR
```
Warnings and errors are intentionally preserved for troubleshooting and auditability.

## 21. Reporting

The reporting system supports two output formats.
```text
se_chain/reporting/
├── json_report.py
└── text_report.py
```
Reports are written to:
```text
output/reports/
```
Each report is associated with a specific run ID.

Example:
```text
output/reports/
├── 20260823-141824-e47ada4f.json
└── 20260823-141824-e47ada4f.txt
```

## 22. JSON Reports

JSON reports are intended for:

- machine processing
- automated analysis
- SIEM-style ingestion
- future integrations
- structured archival

Example validation:
```bash
python -m json.tool output/reports/<run_id>.json
```

A successful command indicates that the generated JSON is syntactically valid.

## 23. Text Reports

Text reports provide a human-readable representation of the simulation.

They are useful for:

internship submission
- analyst review
- demonstrations
- documentation
- manual inspection

## 24. Command-Line Usage

### Show help
```bash
python se_chain.py --help
```
### Show version
```bash
python se_chain.py --version
```

Expected format:
```text
se_chain.py 1.0.0
```
### Run the complete simulation
```bash
python se_chain.py --run-all
```

The command executes the full authorized chain.

Example:
```text
Starting simulation...

Starting module: osint
Starting module: profile
Starting module: phish
Starting module: template

Defensive IR triggered

RUN COMPLETED
```
## 25. Interactive Mode

Running the program without arguments starts the interactive CLI.
```bash
python se_chain.py
```
Menu:
```text
1. Run full simulation
2. Show status
3. Generate report
4. Exit
```
### Option 1 — Run Full Simulation

Runs the complete chain.
```text
1
```
### Option 2 — Show Status

Displays the latest persisted simulation.
```text
2
```
Example:
```text
CURRENT SIMULATION STATUS

Run ID    : 20260823-141824-e47ada4f
Target    : 127.0.0.1
Mode      : lab
Status    : completed
Authorized: True
```
The status command does not execute a new simulation.

### Option 3 — Generate Report

Generates reports for the latest simulation.
```text
3
```
### Option 4 — Exit
```text
4
```
Terminates the interactive CLI.

## 26. Direct Report Generation

Run:
```bash
python se_chain.py --report
```

If no runtime context exists in the current process, the CLI can recover the latest persisted run.

The generated files are written to:
```text
output/reports/
```
## 27. Testing

The project uses __pytest__.

Run the complete test suite:
```bash
pytest -q
```
Current validation result:
```text
23 passed
```
This confirms that the implemented automated tests are passing.

## 28. Compilation Validation

Python source compilation can be checked using:
```bash
python -m compileall -q se_chain tests
```

A successful command produces no error output.

This verifies that the Python source tree can be compiled successfully.

## 29. JSON Validation

A generated report can be validated with:
```bash
python -m json.tool output/reports/<run_id>.json >/dev/null
```

A successful exit indicates valid JSON syntax.

## 30. Recommended Validation Workflow

For a complete verification:
```bash
pytest -q
```
Then:
```bash
python -m compileall -q se_chain tests
```
Then:
```bash
python se_chain.py --run-all
```
Then verify persistence:
```bash
python se_chain.py
```
Select:
```text
2
```
Then generate reports:
```bash
python se_chain.py --report
```
Finally validate JSON:
```bash
python -m json.tool output/reports/<run_id>.json >/dev/null
```

## 31. Example Successful Execution

A successful run produces output similar to:
```text
RUN COMPLETED

Run ID : 20260823-141824-e47ada4f
Status : completed

MODULE STATUS

[+] osint       completed
[+] profile     completed
[+] phish       completed
[+] template    completed
[+] ir          completed

Events generated : 10
IR actions       : 5
Risk score       : 40
Risk level       : MEDIUM
```

The exact run ID and timestamps will vary.

## 32. Output Directory

The simulator produces three primary categories of artifacts:
```text
output/
├── logs/
├── runs/
└── reports/
```
### logs/

Contains application execution logs.
```text
output/logs/se_chain.log
```
### runs/

Contains persisted simulation state.
```text
output/runs/<run_id>.json
```
### reports/

Contains generated reports.
```text
output/reports/<run_id>.json
output/reports/<run_id>.txt
```
## 33. Error Handling

The project uses explicit exception handling and structured error reporting.

Failure conditions are separated from warnings.

Examples:

### Warning
```text
OSINT provider warning
```
The module can still complete successfully.

### Module failure
```text
phish reported failure
```
The chain engine can mark the chain as failed.

### Authorization failure
```text
Simulation blocked: target is not authorized
```
Execution is prevented.

This distinction is important for operational observability.

## 34. Exit Codes

The CLI provides meaningful process exit codes.
```text
0 = successful execution
1 = simulation/application failure
2 = authorization/block condition
130 = interrupted by user
```
This allows the tool to be integrated into shell scripts and automated workflows.

## 35. Reliability Considerations

The project includes several reliability-oriented design decisions:

- modular execution
- structured data models
- explicit error handling
- persistent run state
- atomic state writes
- unique run identifiers
- structured logging
- deterministic report locations
- automated regression tests
- authorization checks
- separate reporting layer

## 36. Maintainability

The application intentionally separates responsibilities.
```text
CLI
    ↓
Engine
    ↓
Modules
    ↓
Models
    ↓
Persistence / Reporting
```
This makes it possible to modify one subsystem without unnecessarily changing the others.

For example:

- reporting can evolve independently from modules
- a module can be tested independently
- persistence can change independently from CLI presentation
- safety policy remains separated from simulation logic

## 37. Extensibility

Additional simulation modules can be introduced without redesigning the entire application.

Potential future modules could include controlled simulations for:

- awareness assessment
- security-event correlation
- detection engineering
- incident triage
- defensive playbook execution
- additional reporting formats

Any future module must remain inside the authorization and laboratory safety boundary.

## 38. Configuration

Laboratory configuration is loaded through:
```text
se_chain/config.py
```
The configured target should remain explicitly authorized.

Before changing a target, verify:
```text
target
target_type
environment
authorized
```
The simulator should never be configured to operate against a target without explicit authorization.

## 39. Troubleshooting

## Problem: pytest command not found

Activate the virtual environment:
```bash
source .venv/bin/activate
```
Then install pytest:
```bash
pip install pytest
```
## Problem: No simulation available

If the CLI displays:
```text
[!] No simulation has been run yet.
```
run:
```bash
python se_chain.py --run-all
```
The run will then be persisted to:
```text
output/runs/
```
## Problem: Report generation fails

Check that:
```text
output/reports/
```
exists and is writable.

Also verify that a simulation has been completed.

## Problem: Run state cannot be loaded

Inspect:
```bash
ls -lh output/runs/
```
Then validate the relevant JSON file:
```bash
python -m json.tool output/runs/<run_id>.json >/dev/null
```
## Problem: OSINT provider warning

A provider warning does not necessarily indicate a simulator failure.

Inspect:
```text
output/logs/se_chain.log
```
for the corresponding run ID and warning message.

## 40. Development Workflow

Recommended development workflow:
```text
Modify code
    ↓
Run tests
    ↓
Compile source
    ↓
Run laboratory simulation
    ↓
Inspect logs
    ↓
Inspect persisted state
    ↓
Generate reports
    ↓
Validate JSON
    ↓
Document changes
```
Commands:
```bash
pytest -q
python -m compileall -q se_chain tests
python se_chain.py --run-all
python se_chain.py --report
```
## 41. Test Evidence

The Day 15 implementation was validated using automated tests and manual CLI verification.

Current automated test result:
```text
23 passed
```
Compilation validation:
```text
python -m compileall -q se_chain tests
```
Simulation validation:
```text
RUN COMPLETED
```
Persistence validation:
```text
CURRENT SIMULATION STATUS
Status    : completed
Authorized: True
```
Reporting validation:
```text
REPORTS GENERATED
```
JSON validation:
```text
python -m json.tool <report>.json
```
## 42. Current Demonstration Metrics

The validated laboratory run produced:
```text
Events generated : 10
IR actions       : 5
Risk score       : 40
Risk level       : MEDIUM
```
These values represent the configured simulation scenario and are not measurements of a real-world target.

## 43. Security Design Principles

The project follows several core security engineering principles:

### Least privilege

The simulator operates against an explicitly authorized laboratory target.

### Defense in depth

Authorization, policy, module validation, logging, and defensive IR simulation provide multiple control layers.

### Fail-safe behavior

Unauthorized execution is blocked.

### Separation of concerns

CLI, engine, modules, persistence, reporting, and safety controls are separated.

### Auditability

Simulation activity is recorded through:

run IDs
structured logs
persisted state
generated reports

### Reproducibility

Each execution produces a unique run identifier and associated artifacts.

## 44. Limitations

This project is a cybersecurity training simulator.

It is not intended to replace:

- enterprise SIEM platforms
- production SOAR platforms
- real incident-response systems
- commercial phishing-awareness platforms
- enterprise case-management systems
- production threat-intelligence platforms

The simulated outputs represent controlled training scenarios.

External provider availability may also affect individual passive-information collection stages.

## 45. Production Readiness Considerations

The current implementation demonstrates production-oriented software engineering practices, but it should not be described as a production security platform.

Before deployment in a real enterprise environment, additional controls would be required, including:

- centralized authentication
- role-based access control
- secure secrets management
- centralized persistent storage
- database-backed run history
- concurrent execution controls
- cryptographic integrity protection
- centralized logging
- monitoring and alerting
- configuration management
- CI/CD integration
- dependency pinning and vulnerability scanning
- formal threat modeling
- security review
- code signing
- deployment hardening
- comprehensive audit controls

These are intentionally outside the scope of the Day 15 internship laboratory.

## 46. Ethical Use

This software is intended for:

- cybersecurity education
- authorized security training
- defensive research
- laboratory exercises
- security-awareness development
- controlled simulation
- incident-response training

Only use the system against systems, infrastructure, and targets for which explicit authorization has been obtained.

The safest default is to use the included localhost laboratory configuration.

## 47. Reproducibility

A clean reproduction of the Day 15 validation can be performed using:
```bash
git clone <repository>
cd day15-se-chain

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install pytest

pytest -q

python -m compileall -q se_chain tests

python se_chain.py --run-all

python se_chain.py --report
```

The exact output timestamps and run IDs will differ between executions.

## 48. Versioning

Current version:
```text
1.0.0
```
The version is displayed by:
```bash
python se_chain.py --version
```
Semantic versioning is recommended for future releases:
```text
MAJOR.MINOR.PATCH
```
## 49. Day 15 Completion Criteria

The Day 15 implementation is considered complete when:

 - Modular chain engine implemented
 - Authorization control implemented
 - OSINT simulation implemented
 - Synthetic profiling implemented
 - Phishing risk analysis implemented
 - Security-awareness template generation implemented
 - Defensive IR simulation implemented
 - Structured logging implemented
 - Persistent run state implemented
 - JSON reporting implemented
 - Text reporting implemented
 - Interactive CLI implemented
 - Command-line execution implemented
 - Automated tests passing
 - Python compilation verified
 - Cross-process persistence verified
 - Report generation verified
 - JSON output validated
## 50. Final Validation

The final Day 15 validation produced:
```text
pytest -q
23 passed

python -m compileall -q se_chain tests
PASS

python se_chain.py --run-all
RUN COMPLETED

Events generated : 10
IR actions       : 5
Risk score       : 40
Risk level       : MEDIUM

python se_chain.py
Option 2
PERSISTED RUN RECOVERED

python se_chain.py --report
REPORTS GENERATED

python -m json.tool <report>.json
VALID JSON
```
## 51. Conclusion

SE Chain Simulator demonstrates how a controlled social-engineering scenario can be modeled as a modular cybersecurity workflow while maintaining explicit authorization and defensive boundaries.

The completed Day 15 implementation combines:
```text
Authorization
      +
Modular Security Analysis
      +
Risk Assessment
      +
Defensive IR Simulation
      +
Persistent State
      +
Structured Logging
      +
Automated Testing
      +
Machine/Human Reports
```
The result is a reproducible laboratory framework suitable for cybersecurity education, internship demonstration, security-awareness exercises, and defensive engineering practice.

### Project Status
```text
Version : 1.0.0
Phase   : Internship Phase 6 — Deliverables
Day     : 15
Mode    : Authorized Laboratory Simulation
Status  : COMPLETE
Tests   : 23 passed
```
### Built for authorized cybersecurity training and defensive security engineering.