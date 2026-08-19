# Day 08 — USB Drop Attack Simulation

## Overview

This lab demonstrates the concept of a USB drop attack through a controlled, benign Python payload simulation.

A USB drop attack relies on social engineering to convince a target to connect or execute content from an unknown removable device. If malicious code is executed, it may attempt to collect information about the host.

This lab safely demonstrates that post-execution concept by collecting a small set of non-sensitive local system metadata and writing it to a local evidence file.

The simulation does **not** implement:

- AutoRun or AutoPlay abuse
- Persistence
- Credential harvesting
- Privilege escalation
- Malware deployment
- Command execution beyond the simulator itself
- Data exfiltration
- Command-and-control communication

The exercise is intended for cybersecurity training and security-awareness purposes only.

---

## Objectives

- Understand the USB drop attack concept.
- Understand how social engineering can be combined with removable media.
- Demonstrate benign post-execution host information collection.
- Generate local evidence of the simulated payload execution.
- Identify defensive controls against USB-based attacks.

---

## Attack Concept

A simplified USB drop attack can be represented as:

```text
Unknown USB Device
        |
        v
Target discovers device
        |
        v
Social engineering encourages interaction
        |
        v
User executes unknown content
        |
        v
Payload executes
        |
        v
Host information may be collected
This lab simulates only the final stage in a safe manner.

Benign simulator
       |
       v
Collect local metadata
       |
       v
Write recon_log.txt
       |
       v
Review evidence
Simulated Information Collection

The payload collects the following local metadata:

Field	Description
timestamp	Time at which the simulator executed
hostname	Hostname of the local system
os	Operating system family
version	Operating system version information
user	Current local username
cwd	Current working directory

The collected information is written to:

output/recon_log.txt
Project Structure
day08-usb-drop/
├── output/
│   └── recon_log.txt
├── report/
│   └── day08-report.md
├── screenshots/
│   ├── recon-log.png
│   ├── simulator-execution.png
│   └── verification.png
├── requirements.txt
└── usb_payload_simulator.py
Requirements
Python 3.10+
Linux, Windows, or another supported Python environment

The simulator uses only Python standard-library modules.

No external Python packages are required.

Modules Used

The simulator uses:

datetime
os
platform
socket
pathlib
argparse

These modules are used only for local metadata collection, file handling, and command-line argument processing.

Usage

From the project directory:

python3 usb_payload_simulator.py

The simulator writes the resulting evidence to:

output/recon_log.txt

To specify another output file:

python3 usb_payload_simulator.py --output output/custom_log.txt
Example Output

The generated report follows this structure:

timestamp: <execution timestamp>
hostname: <local hostname>
os: <operating system>
version: <system version>
user: <local username>
cwd: <working directory>

The actual values depend on the system on which the simulator is executed.

Evidence

The lab includes the following screenshots:

Simulator Execution

screenshots/simulator-execution.png

Shows the successful execution of the benign USB payload simulator.

Generated Reconnaissance Log

screenshots/recon-log.png

Shows the local metadata written to output/recon_log.txt.

Verification

screenshots/verification.png

Shows the simulator verification and generated output artifact.

Defensive Considerations

Organizations can reduce USB-based attack risk through a combination of technical controls and user awareness.

Disable or Restrict Automatic Execution

Automatic execution mechanisms should be restricted or disabled where appropriate so that simply connecting removable media does not automatically execute untrusted content.

Endpoint Protection

Endpoint security and EDR solutions can monitor suspicious processes, scripts, removable-media activity, and abnormal behavior.

Device Control

Organizations can restrict which USB storage devices are permitted on corporate systems.

Application Control

Application allowlisting can prevent unauthorized executables or scripts from running.

Data Loss Prevention

DLP controls can help detect and restrict unauthorized movement of sensitive information.

Security Awareness Training

Users should be trained not to connect unknown USB devices or execute unknown files found on removable media.

Security Boundary

This project is intentionally limited to a benign local simulation.

It does not create an actual USB autorun mechanism and does not attempt to bypass operating-system security controls.

The generated information remains on the local system and is written only to the specified output file.

Testing should be performed only on systems that you own or are explicitly authorized to assess.

Learning Outcome

This lab demonstrates how a USB drop attack can combine:

Physical access
      +
Social engineering
      +
User execution
      =
Potential payload execution

The simulator demonstrates the potential post-execution information-collection stage without implementing a malicious payload.

Conclusion

The Day 08 lab provides a controlled demonstration of USB drop attack concepts and the importance of removable-media security.

The exercise reinforces that technical controls alone are not sufficient. Secure USB policies, endpoint protection, device controls, application controls, and user awareness should work together to reduce the risk of USB-based attacks.
