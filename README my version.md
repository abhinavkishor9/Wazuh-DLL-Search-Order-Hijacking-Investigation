# Wazuh-DLL-Search-Order-Hijacking-Investigation
## Overview

DLL Search Order Hijacking occurs when a legitimate Windows application loads a malicious DLL from an attacker-controlled location because of the way Windows searches for DLL dependencies.

The investigation focuses on determining whether a DLL was loaded from an unexpected directory, identifying the process responsible for loading it, validating the DLL on disk, and deciding whether the evidence supports confirmed malicious activity, suspicious activity, or an inconclusive finding.


This lab investigates a controlled DLL loading scenario on a Windows endpoint using PowerShell, Sysmon, and Wazuh.

The investigation focuses on DLL creation, file integrity, digital signature validation, process telemetry, and DLL loading visibility.

The lab also demonstrates an important SOC investigation principle:

> Follow the evidence, not the assumption.

The presence of an unsigned DLL in a custom directory is not automatically proof of malicious activity. The analyst must correlate multiple sources of evidence before determining whether DLL Search Order Hijacking actually occurred.

---

## Lab Objectives

- Understand the concept of DLL Search Order Hijacking and how Windows applications can be affected by DLL loading behavior.
- Create a controlled DLL loading scenario in an isolated Windows laboratory environment.
- Use PowerShell to create, inspect, hash, and load the test DLL.
- Monitor DLL-related activity using Sysmon and Wazuh.
- Investigate Sysmon Event ID 11 for DLL file creation activity.
- Investigate Sysmon Event ID 1 for process creation and execution context.
- Check Sysmon Event ID 7 for DLL Image Load telemetry.
- Correlate file, process, DLL, and timestamp evidence.
- Validate the DLL using SHA256 hashing and digital signature checks.
- Identify telemetry gaps when expected Image Load events are unavailable.
- Distinguish controlled DLL loading from confirmed DLL Search Order Hijacking.
- Apply an evidence-based verdict without overclaiming malicious activity.
- Map confirmed DLL Search Order Hijacking behavior to MITRE ATT&CK T1574.001.
- Document investigation findings, limitations, and troubleshooting steps.
---

## Lab Environment

- Windows laboratory VM
- Wazuh Agent
- Wazuh Manager
- Wazuh Dashboard
- Sysmon
- PowerShell
- Controlled DLL test environment

---

## Lab Directory

The laboratory directory used during the investigation was:

    C:\DLLHijackLab

The test DLL was:

    C:\DLLHijackLab\TestLibrary.dll

---

## Scenario

A SOC analyst is investigating unusual DLL activity on a Windows endpoint monitored by Wazuh and Sysmon. A test DLL has been created inside a dedicated laboratory directory and loaded through PowerShell to simulate the type of endpoint artifacts that may appear during a DLL hijacking investigation.

The analyst must determine whether the observed activity represents legitimate or controlled DLL loading, or whether the available evidence supports DLL Search Order Hijacking. The investigation focuses on correlating the DLL's creation time, file path, SHA256 hash, digital signature, process creation events, and available Image Load telemetry.

During the investigation, Sysmon records the creation of `TestLibrary.dll` through Event ID 11, while multiple process creation events are available through Event ID 1. However, a search for a matching Sysmon Event ID 7 Image Load event does not return evidence for the laboratory DLL. This creates an important telemetry gap that must be documented rather than assumed.

The investigation therefore requires the analyst to:

- Establish when and where the DLL was created.
- Validate the DLL hash and digital signature.
- Identify the process activity surrounding the DLL loading operation.
- Check whether Sysmon recorded the DLL as an Image Load.
- Review the corresponding Wazuh telemetry.
- Correlate the available evidence into a timeline.
- Determine what can and cannot be proven from the collected telemetry.
- Assess whether the activity supports MITRE ATT&CK T1574.001.
- Produce an evidence-based verdict without overclaiming malicious behavior.

> **Investigation principle:** Follow the evidence, not the assumption.

---

## Environment Validation

### Wazuh Agent

Command:

    Get-Service WazuhSvc

Result:

    Status   Name
    Running  WazuhSvc

### Sysmon

Command:

    Get-Service Sysmon64

Result:

    Status   Name
    Running  Sysmon64

Both monitoring services were running during the investigation.

---

## Laboratory Directory Creation

The directory was created using PowerShell:

    New-Item -ItemType Directory -Path C:\DLLHijackLab -Force

The directory was successfully created:

    C:\DLLHijackLab

Creation time:

    12 September 2026 07:46

---

## DLL Artifact

The test DLL was:

    C:\DLLHijackLab\TestLibrary.dll

File details:

| Property | Value |
|---|---|
| File name | TestLibrary.dll |
| Path | C:\DLLHijackLab\TestLibrary.dll |
| Size | 2560 bytes |
| Creation time | 12 September 2026 07:48:12 |
| Last write time | 12 September 2026 07:48:12 |

---

## SHA256 Hash

The DLL hash was calculated using PowerShell:

    Get-FileHash C:\DLLHijackLab\TestLibrary.dll -Algorithm SHA256

SHA256:

    8423129446749C595A4AB5356B5B4EC454D8AE332161E00B5A229A28E1A208F8

This hash was recorded as the unique identifier for the test artifact.

---

## Digital Signature

The DLL signature was checked using:

    Get-AuthenticodeSignature C:\DLLHijackLab\TestLibrary.dll

Result:

    Status: NotSigned

The DLL was unsigned.

This result is an attribute of the controlled test artifact and is not, by itself, proof of malicious activity.

---

## DLL Loading

The DLL was loaded using:

    $assembly = [System.Reflection.Assembly]::LoadFrom("C:\DLLHijackLab\TestLibrary.dll")

The assembly loaded successfully.

The assembly name returned by PowerShell was:

    dsaukks5.ktx, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null

The test class was accessed using:

    $type = $assembly.GetType("DLLHijackLab.Test")

The test method was invoked using:

    $type.GetMethod("Run").Invoke($null, $null)

Observed output:

    DLL Hijack Lab test assembly loaded.

Execution timestamp:

    12 September 2026 07:52:06

---

## Sysmon Investigation

### Event ID 11 - File Creation

The following query was used:

    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object {
        $_.Id -eq 11 -and
        $_.Message -match "DLLHijackLab"
    } |
    Select-Object TimeCreated,Message

A matching Event ID 11 record was observed:

    12-09-2026 07:48:12

This provides evidence that file creation activity involving the laboratory directory was recorded by Sysmon.

---

## Sysmon Event Metadata

The observed event contained the following metadata:

    data.win.system.computer       DESKTOP-9MMM37V
    data.win.system.eventID        11
    data.win.system.eventRecordID  257687
    data.win.system.keywords       0x8000000000000000
    data.win.system.level          4

The event was identified as:

    Sysmon Event ID 11 - File created

---

## Event ID 1 - Process Creation

Process creation telemetry was investigated using:

    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object {$_.Id -eq 1} |
    Select-Object -First 20 TimeCreated,Id,Message

Multiple Event ID 1 records were available around the investigation period.

Observed events covered approximately:

    07:51:59
    to
    07:53:02

Event ID 1 can provide:

- Process name
- Process path
- Command line
- Process ID
- Parent process ID
- Parent process
- Execution timestamp

This telemetry can be used to establish the process execution timeline.

---

## Event ID 7 - Image Load

Sysmon Event ID 7 was searched to determine whether the DLL was recorded as an Image Load event.

Query:

    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object {
        $_.Id -eq 7 -and
        $_.Message -match "DLLHijackLab"
    } |
    Select-Object TimeCreated,Message

Result:

    No matching event returned

This is an important evidence gap.

The available Sysmon telemetry did not independently demonstrate that TestLibrary.dll was recorded as an Image Load event.

---

## Wazuh Investigation

The laboratory directory was used as the primary search indicator in Wazuh:

    DLLHijackLab

Event ID searches can be narrowed using:

    win.system.eventID:11

    win.system.eventID:1

    win.system.eventID:7

The exact searchable field names should be validated against the current Wazuh event schema rather than assumed.

The absence of a Wazuh result should not automatically be interpreted as absence of endpoint activity.

---

## Evidence Summary

| Evidence | Result |
|---|---|
| Wazuh Agent | Running |
| Sysmon | Running |
| Laboratory directory | C:\DLLHijackLab |
| Test DLL | TestLibrary.dll |
| DLL size | 2560 bytes |
| SHA256 | 8423129446749C595A4AB5356B5B4EC454D8AE332161E00B5A229A28E1A208F8 |
| Digital signature | NotSigned |
| DLL loading | Successful |
| Sysmon Event ID 11 | Observed |
| Sysmon Event ID 1 | Available |
| Sysmon Event ID 7 | No matching event observed |
| Native DLL Search Order Hijacking | Not confirmed |

---

## Investigation Assessment

The exercise successfully demonstrated controlled DLL creation and loading.

However, the loading mechanism used:

    [System.Reflection.Assembly]::LoadFrom()

This explicitly loads the .NET assembly from the specified path.

Therefore, successful execution of this command does not demonstrate Windows DLL search-order resolution.

The missing Event ID 7 telemetry also prevents an independent confirmation that the test DLL was observed as a Windows Image Load event.

---

## MITRE ATT&CK

Potential technique:

    T1574.001 - DLL Search Order Hijacking

The technique is relevant to the investigation objective, but the available evidence does not support claiming confirmed T1574.001 activity.

---

