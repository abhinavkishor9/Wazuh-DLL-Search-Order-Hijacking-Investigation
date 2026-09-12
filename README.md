# Wazuh DLL Search Order Hijacking Investigation

## Overview

This lab investigates a controlled DLL loading scenario on a Windows endpoint using PowerShell, Sysmon, and Wazuh.

The investigation focuses on DLL creation, file integrity, digital signature validation, process telemetry, and DLL loading visibility.

The lab also demonstrates an important SOC investigation principle:

> Follow the evidence, not the assumption.

The presence of an unsigned DLL in a custom directory is not automatically proof of malicious activity. The analyst must correlate multiple sources of evidence before determining whether DLL Search Order Hijacking actually occurred.

---

## Lab Objectives

- Create a controlled DLL investigation artifact.
- Store the artifact in an isolated laboratory directory.
- Calculate the DLL SHA256 hash.
- Check the DLL digital signature.
- Load the DLL using PowerShell.
- Monitor the activity using Sysmon.
- Investigate Sysmon Event ID 11.
- Investigate Sysmon Event ID 1.
- Check Sysmon Event ID 7 for Image Load telemetry.
- Review Wazuh visibility.
- Correlate timestamps and artifacts.
- Identify telemetry gaps.
- Avoid unsupported conclusions.
- Assess whether DLL Search Order Hijacking can be confirmed.
- Map relevant behavior to MITRE ATT&CK T1574.001 when supported by evidence.

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

A controlled DLL loading exercise was performed on a Windows laboratory endpoint.

A test DLL was created inside an isolated directory and subsequently loaded using PowerShell and the .NET Assembly loading mechanism.

After the activity was performed, Sysmon and Wazuh telemetry were reviewed to determine which artifacts were generated and whether the available telemetry was sufficient to prove DLL Search Order Hijacking.

The DLL was successfully created and loaded. Sysmon recorded file creation activity through Event ID 11, and multiple process creation events were available through Event ID 1.

However, a search for a matching Sysmon Event ID 7 Image Load event returned no result.

The investigation therefore demonstrates controlled DLL loading activity, but the available evidence does not independently confirm native Windows DLL Search Order Hijacking.

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

## Final Verdict

    Activity: Controlled DLL Loading
    DLL: TestLibrary.dll
    Location: C:\DLLHijackLab\TestLibrary.dll
    SHA256: 8423129446749C595A4AB5356B5B4EC454D8AE332161E00B5A229A28E1A208F
    Signature: NotSigned
    File Creation Evidence: Confirmed
    Process Creation Telemetry: Available
    Image Load Event ID 7: Not Observed
    DLL Search Order Hijacking: Not Confirmed
    Investigation Status: Inconclusive

---

## Key SOC Lessons

### Artifact Is Not Proof

An unsigned DLL in a custom directory is an investigation indicator, not automatically proof of malicious activity.

### Correlation Matters

A strong DLL investigation should correlate:

    File Creation
        +
    Process Creation
        +
    Image Load
        +
    File Hash
        +
    Digital Signature
        +
    Process Relationship
        +
    Timeline
        +
    Follow-on Activity

### Telemetry Gaps Matter

If Event ID 7 is unavailable or does not contain the expected event, the analyst should document the limitation instead of assuming that the DLL was loaded by a particular process.

### Do Not Overclaim

The exercise demonstrated controlled DLL loading, but the available evidence does not justify claiming a confirmed DLL Search Order Hijacking event.

> Follow the evidence, not the assumption.
