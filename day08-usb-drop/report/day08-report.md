# Day 08 — USB Drop Attack Simulation Report

## 1. Executive Summary

This lab demonstrates the concept of a USB drop attack using a controlled and benign Python payload simulation.

USB drop attacks rely on social engineering to encourage a target to interact with an unknown removable device. If the target executes malicious content, the payload may attempt to collect information from the host.

The implemented simulator demonstrates this concept safely by collecting a limited set of non-sensitive local system metadata and writing the information to a local evidence file.

No actual USB autorun mechanism, persistence, credential harvesting, privilege escalation, data exfiltration, or command-and-control functionality was implemented.

---

## 2. Objective

The objectives of the exercise were to:

1. Understand the USB drop attack technique.
2. Understand the role of social engineering in removable-media attacks.
3. Simulate benign post-execution host information collection.
4. Generate local evidence of the simulated payload execution.
5. Identify defensive controls against USB-based attacks.

---

## 3. Lab Environment

| Component | Configuration |
|---|---|
| Operating System | Parrot OS |
| Runtime | Python 3 |
| Execution Environment | Local virtual machine |
| Network Requirement | None |
| Payload Type | Benign simulation |
| Output | Local text file |

The simulator uses only Python standard-library modules.

---

## 4. Threat Scenario

A simplified USB drop scenario is:

```text
Unknown USB
     |
     v
Target discovers USB
     |
     v
Social engineering encourages interaction
     |
     v
Unknown content is executed
     |
     v
Payload executes
     |
     v
Host information may be collected

The lab does not reproduce the malicious execution mechanism.

Instead, the payload is executed manually in the controlled laboratory environment:

Manual execution
       |
       v
Benign Python simulator
       |
       v
Collect local metadata
       |
       v
Write evidence file
5. Implementation

The simulator is implemented in:

usb_payload_simulator.py

The program collects the following information:

Execution timestamp
Hostname
Operating system
Operating system version
Current username
Current working directory

The information is stored in:

output/recon_log.txt
6. Execution

The simulator was executed from the Day 08 project directory using:

python3 usb_payload_simulator.py

The program completed successfully and generated:

output/recon_log.txt

The generated file was then inspected to verify that the expected metadata had been recorded.

7. Evidence
7.1 Simulator Execution

Screenshot: screenshots/simulator-execution.png

This evidence demonstrates successful execution of the benign USB payload simulator.

The terminal output confirms that the simulation completed and identifies the generated output file.

7.2 Generated Reconnaissance Log

Screenshot: screenshots/recon-log.png

This evidence demonstrates that the simulator successfully generated a local reconnaissance-style log containing the collected system metadata.

The information remains on the local laboratory system.

7.3 Verification

Screenshot: screenshots/verification.png

This evidence demonstrates verification of the Python simulator and the generated output artifact.

8. Collected Data

The simulator collects limited, non-sensitive host metadata.

Data	Purpose
Timestamp	Records when the simulation executed
Hostname	Identifies the local host
OS	Identifies the operating-system family
Version	Records system version information
User	Identifies the local execution account
CWD	Identifies the simulator's working directory

This information demonstrates the type of basic host reconnaissance that could occur after successful execution of a malicious payload.

9. Security Analysis

The exercise demonstrates an important security principle:

Physical access and social engineering can become an initial delivery mechanism for malicious code.

A USB device does not need to exploit a sophisticated vulnerability to become dangerous. A successful attack may instead depend on convincing a user to trust and execute content from an unknown device.

The simulated payload demonstrates how even basic host metadata can be collected after execution.

10. Defensive Controls
10.1 Restrict Automatic Execution

Automatic execution mechanisms should be disabled or restricted where appropriate.

Users should not assume that removable media is safe simply because it was physically connected to a computer.

10.2 USB Device Control

Organizations can restrict removable-media access and allow only approved devices.

10.3 Endpoint Protection

EDR and endpoint security solutions can monitor suspicious processes, scripts, and removable-media activity.

10.4 Application Control

Application allowlisting can reduce the ability of unauthorized executables or scripts to run.

10.5 Data Loss Prevention

DLP controls can help detect and prevent unauthorized movement of sensitive information.

10.6 Security Awareness

Users should be trained to:

Avoid unknown USB devices.
Avoid opening unknown files from removable media.
Report suspicious devices to security personnel.
Follow organizational removable-media policies.
11. Security Boundary

This was a controlled laboratory simulation.

The project intentionally does not implement:

Real USB autorun behavior
Persistence
Credential collection
Privilege escalation
Malware installation
Data exfiltration
Command-and-control communication
Security-control bypass techniques

The simulator only collects basic local system metadata and writes it to a local file.

12. Result

The exercise successfully demonstrated the intended behavior.

Result Summary
Payload simulation        : PASS
Local metadata collection : PASS
Evidence generation       : PASS
Output file generation    : PASS
External communication    : NONE
Persistence               : NONE
Credential collection     : NONE

The generated evidence confirms that the benign payload simulator executed successfully and created the expected local reconnaissance log.

13. Conclusion

The Day 08 exercise demonstrated the security risks associated with USB drop attacks while maintaining a controlled and non-malicious implementation.

The main lesson is that removable-media attacks combine technical and human factors. Even when a device itself appears harmless, social engineering can convince a user to execute untrusted content.

Effective defense therefore requires multiple layers:

User Awareness
      +
USB Device Controls
      +
Endpoint Protection
      +
Application Control
      +
Security Policies
      =
Reduced USB Attack Risk

The lab successfully demonstrated the post-execution information-collection concept without implementing an actual malicious payload.
