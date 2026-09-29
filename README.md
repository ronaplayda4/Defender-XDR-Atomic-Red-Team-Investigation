# Microsoft Defender XDR – Atomic Red Team Investigation

## Project Overview

This project documents a hands-on SOC investigation performed in a
Microsoft Defender XDR lab environment.

Atomic Red Team was used to generate controlled adversary behavior against
a Windows endpoint. Microsoft Defender XDR detected the activity, correlated
multiple alerts into a high-severity incident, and initiated automated
Attack Disruption actions.

> **Lab Notice:** This was an authorized cybersecurity simulation conducted
> in a controlled lab environment. It was not a real-world compromise.

---

## Incident Summary

- **Platform:** Microsoft Defender XDR
- **Severity:** High
- **Correlated Alerts:** 16
- **Evidence Objects:** 33
- **Affected Assets:** 2
- **Primary Technique:** MITRE ATT&CK T1547.001 – Registry Run Keys / Startup Folder
- **Verdict:** True Positive – Authorized Security Simulation

All usernames, hostnames, IP addresses, tenant information, SIDs, and other
environment-specific identifiers shown in this repository have been
sanitized.

---

## Investigation Timeline

| Time | Activity |
|---|---|
| 09:56:45 AM | First activity recorded by Defender |
| 10:48:09 AM | PowerShell/startup-related activity observed |
| 10:48:10 AM | Additional startup artifact activity |
| 10:48:12 AM | cmd.exe registry-related activity |
| 10:48:14–10:48:18 AM | Concentrated PowerShell, cmd.exe, and reg.exe activity |
| ~10:50 AM | Defender Attack Disruption contained the affected user |
| 10:55:44 AM | RDP Session ID 4 stopped/disconnected |
| ~11:04 AM | Defender isolated the endpoint |

Times are preserved as displayed in Microsoft Defender XDR.

---

## Investigation Workflow

The investigation followed a focused SOC workflow:

1. Triaged the high-severity incident.
2. Reviewed the Defender Attack Story.
3. Examined correlated alerts and affected assets.
4. Analyzed the process tree.
5. Reviewed Evidence and Response artifacts.
6. Investigated PowerShell, cmd.exe, and reg.exe activity.
7. Reviewed persistence-related registry and startup artifacts.
8. Validated remote-session evidence.
9. Used targeted Advanced Hunting to validate important findings.
10. Reviewed automated Attack Disruption actions.
11. Determined the final verdict.

---

## Key Findings

The investigation identified:

- PowerShell execution
- Command Prompt execution
- Registry modification through reg.exe
- Startup/persistence-related artifacts
- Remote-session telemetry
- File activity
- Automated user containment
- RDP disruption
- Endpoint isolation

Process relationships and command-line evidence were consistent with the
authorized Atomic Red Team exercise.

---

## Advanced Hunting

Advanced Hunting was used as a validation step rather than reviewing every
endpoint event individually.

```kusto
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "cmd.exe", "reg.exe", "calc.exe")
| project Timestamp,
          FileName,
          ProcessId,
          ProcessCommandLine,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessId
| order by Timestamp desc
```


## Analyst Assessment

**Verdict:** True Positive – Authorized Security Simulation

**MITRE ATT&CK:** T1547.001 – Registry Run Keys / Startup Folder

**Response:** User contained, RDP activity disrupted, and endpoint isolated.

Microsoft Defender XDR successfully detected and disrupted attacker-like
behavior generated during the authorized Atomic Red Team simulation.

No conclusion of unauthorized external compromise was made from the evidence
reviewed.

---

## Skills Demonstrated

- Microsoft Defender XDR
- Incident triage
- Attack Story analysis
- Process-tree analysis
- Endpoint investigation
- Advanced Hunting / KQL
- Registry persistence investigation
- MITRE ATT&CK mapping
- Incident scoping
- Attack Disruption analysis
- SOC investigation reporting
