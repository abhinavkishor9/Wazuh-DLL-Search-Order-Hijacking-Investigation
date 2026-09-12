# Investigation Notes - DLL Search Order Hijacking

## Investigation Overview

This investigation examined a controlled DLL loading scenario on a Windows laboratory endpoint using PowerShell, Sysmon, and Wazuh.

The objective was to determine what endpoint evidence was generated when a test DLL was created and loaded and whether the available telemetry was sufficient to confirm DLL Search Order Hijacking.

The investigation followed an evidence-based approach and did not treat the presence of an unsigned DLL in a custom directory as proof of malicious activity.

---

## 1. Environment Validation

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

Both monitoring services were running.

---

## 2. Laboratory Directory

The laboratory directory was created using:

    New-Item -ItemType Directory -Path C:\DLLHijackLab -Force

Directory:

    C:\DLLHijackLab

Creation time:

    12 September 2026 07:46

---

## 3. DLL Artifact

The test DLL was identified as:

    C:\DLLHijackLab\TestLibrary.dll

File size:

    2560 bytes

Creation time:

    12 September 2026 07:48:12

Last write time:

    12 September 2026 07:48:12

---

## 4. Hash Validation

The hash was calculated using:

    Get-FileHash C:\DLLHijackLab\TestLibrary.dll -Algorithm SHA256

SHA256:

    8423129446749C595A4AB5356B5B4EC454D8AE332161E00B5A229A28E1A208F

The hash was recorded for artifact identification and investigation tracking.

---

## 5. Digital Signature

The DLL was checked using:

    Get-AuthenticodeSignature C:\DLLHijackLab\TestLibrary.dll

Result:

    Status: NotSigned

The DLL was unsigned.

Because this was a controlled laboratory artifact, the unsigned status was expected.

The signature result alone does not establish maliciousness.

---

## 6. DLL Loading Activity

The DLL was loaded using:

    $assembly = [System.Reflection.Assembly]::LoadFrom("C:\DLLHijackLab\TestLibrary.dll")

The assembly loaded successfully.

The assembly name returned was:

    dsaukks5.ktx, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null

The test class was accessed using:

    $type = $assembly.GetType("DLLHijackLab.Test")

The test method was invoked using:

    $type.GetMethod("Run").Invoke($null, $null)

Observed output:

    DLL Hijack Lab test assembly loaded.

Execution time:

    12 September 2026 07:52:06

---

## 7. Sysmon Event ID 11

Sysmon Event ID 11 was investigated for file creation.

Query:

    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object {
        $_.Id -eq 11 -and
        $_.Message -match "DLLHijackLab"
    } |
    Select-Object TimeCreated,Message

Observed result:

    12-09-2026 07:48:12

The event indicates that Sysmon recorded file creation activity associated with the laboratory directory.

---

## 8. Sysmon Event Metadata

The observed event contained:

    Computer:
    DESKTOP-9MMM37V

    Event ID:
    11

    Event Record ID:
    257687

    Keywords:
    0x8000000000000000

    Level:
    4

The event was identified as:

    File created

---

## 9. Sysmon Event ID 1

Process creation telemetry was queried using:

    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object {$_.Id -eq 1} |
    Select-Object -First 20 TimeCreated,Id,Message

Multiple Event ID 1 records were available around the investigation period.

The events covered approximately:

    07:51:59 - 07:53:02

Relevant fields to investigate include:

- Process name
- Process path
- Command line
- Process ID
- Parent Process ID
- Parent process
- Timestamp

---

## 10. Sysmon Event ID 7

Event ID 7 was searched to identify Image Load telemetry.

Query:

    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object {
        $_.Id -eq 7 -and
        $_.Message -match "DLLHijackLab"
    } |
    Select-Object TimeCreated,Message

Result:

    No matching event returned

This means that a matching Image Load event was not observed through the query.

This does not prove that the DLL was never loaded. It means that the expected Sysmon Image Load evidence was not available through the observed telemetry.

---

## 11. Wazuh Evidence

The laboratory indicator used for searching Wazuh was:

    DLLHijackLab

Event IDs of interest were:

    11 - File Creation
    1  - Process Creation
    7  - Image Load

The actual Wazuh field names should be validated against the current event schema.

---

## 12. Timeline

| Time | Activity | Evidence |
|---|---|---|
| 07:46 | Laboratory directory created | PowerShell |
| 07:48:12 | Test DLL created | Sysmon Event ID 11 |
| 07:48:12 | DLL creation and modification timestamp | File metadata |
| 07:52:06 | DLL loading activity performed | PowerShell |
| 07:51:59 - 07:53:02 | Process creation events available | Sysmon Event ID 1 |
| Investigation period | Event ID 7 searched | Sysmon |
| Investigation period | No matching Event ID 7 observed | Telemetry gap |

---

## 13. Confirmed Evidence

The following evidence is confirmed:

- Wazuh Agent was running.
- Sysmon was running.
- The laboratory directory was created.
- TestLibrary.dll existed.
- The DLL was 2560 bytes.
- The SHA256 hash was recorded.
- The DLL was unsigned.
- The DLL was successfully loaded through PowerShell.
- Sysmon Event ID 11 recorded file creation activity.
- Sysmon Event ID 1 process telemetry was available.

---

## 14. Unconfirmed Evidence

The following could not be confirmed:

- Native Windows DLL Search Order Hijacking.
- Sysmon Event ID 7 Image Load for TestLibrary.dll.
- Malicious execution.
- Persistence.
- Privilege escalation.
- Credential access.
- Network communication caused by the DLL.
- Follow-on malicious activity.

---

## 15. Investigation Assessment

The evidence supports controlled DLL creation and loading.

However, the DLL was loaded using the explicit .NET method:

    [System.Reflection.Assembly]::LoadFrom()

This does not independently demonstrate DLL Search Order Hijacking.

A true DLL Search Order Hijacking investigation requires evidence showing that an application searched for and loaded an unexpected DLL because of Windows DLL resolution behavior.

That evidence was not established during this exercise.

---

## 16. MITRE ATT&CK

Potential technique:

    T1574.001 - DLL Search Order Hijacking

Assessment:

    Not confirmed

The technique remains the investigation objective rather than a confirmed observation.

---

## 17. Final Investigation Verdict

    Verdict: Inconclusive

Reason:

    Controlled DLL loading was confirmed, but native DLL Search Order
    Hijacking was not independently demonstrated.

Primary evidence gap:

    No matching Sysmon Event ID 7 Image Load event was observed.

---

## 18. SOC Analyst Takeaway

The investigation demonstrates why endpoint investigations should be based on correlated evidence.

The correct reasoning is:

    DLL exists
        ↓
    DLL creation observed
        ↓
    DLL loaded through PowerShell
        ↓
    Process telemetry available
        ↓
    Image Load telemetry not observed
        ↓
    Native DLL Search Order Hijacking cannot be confirmed

The correct conclusion is therefore:

> Confirm what the telemetry proves, document what it cannot prove, and avoid filling evidence gaps with assumptions.
