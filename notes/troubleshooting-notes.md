# Troubleshooting Notes - DLL Search Order Hijacking Investigation

## Overview

This document records the issues, limitations, and investigation decisions encountered while building and analyzing the DLL Search Order Hijacking lab.

The main investigation challenge was distinguishing between successful DLL loading and evidence of actual Windows DLL Search Order Hijacking.

---

## 1. Wazuh Agent Check

### Command

    Get-Service WazuhSvc

### Result

    Status   Name
    Running  WazuhSvc

### Assessment

The Wazuh Agent was running.

No Wazuh service failure was identified at the beginning of the lab.

---

## 2. Sysmon Check

### Command

    Get-Service Sysmon64

### Result

    Status   Name
    Running  Sysmon64

### Assessment

Sysmon was running.

Therefore, the absence of a specific event could not immediately be attributed to the Sysmon service being stopped.

---

## 3. Laboratory Directory

The directory was successfully created:

    New-Item -ItemType Directory -Path C:\DLLHijackLab -Force

Result:

    C:\DLLHijackLab

No directory creation problem was encountered.

---

## 4. DLL Creation

The test DLL was successfully created:

    C:\DLLHijackLab\TestLibrary.dll

File size:

    2560 bytes

The DLL was available for subsequent testing.

---

## 5. Hash Calculation

The following command worked successfully:

    Get-FileHash C:\DLLHijackLab\TestLibrary.dll -Algorithm SHA256

SHA256:

    8423129446749C595A4AB5356B5B4EC454D8AE332161E00B5A229A28E1A208F

The hash was recorded as the identifier for the test artifact.

---

## 6. Digital Signature Check

The following command was used:

    Get-AuthenticodeSignature C:\DLLHijackLab\TestLibrary.dll

Result:

    Status: NotSigned

### Interpretation

The DLL was unsigned.

This was expected for the controlled laboratory artifact.

An unsigned DLL should not automatically be classified as malicious without supporting evidence.

---

## 7. DLL Loading

The DLL was loaded using:

    $assembly = [System.Reflection.Assembly]::LoadFrom("C:\DLLHijackLab\TestLibrary.dll")

The assembly loaded successfully.

The test method was invoked using:

    $type = $assembly.GetType("DLLHijackLab.Test")
    $type.GetMethod("Run").Invoke($null, $null)

Observed output:

    DLL Hijack Lab test assembly loaded.

### Important Finding

The loading mechanism used:

    Assembly.LoadFrom()

This explicitly specifies the DLL path.

Therefore, successful loading does not demonstrate Windows DLL Search Order Hijacking.

---

## 8. Sysmon Event ID 11 Worked

The following query returned a matching event:

    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object {
        $_.Id -eq 11 -and
        $_.Message -match "DLLHijackLab"
    } |
    Select-Object TimeCreated,Message

Observed event:

    12-09-2026 07:48:12

### Assessment

Sysmon was successfully recording file creation activity.

This confirms that the endpoint generated observable telemetry for the creation of the laboratory DLL.

---

## 9. Sysmon Event ID 1 Was Available

The following query returned multiple process creation events:

    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object {$_.Id -eq 1} |
    Select-Object -First 20 TimeCreated,Id,Message

Events were available around:

    07:51:59 - 07:53:02

### Assessment

Process creation telemetry was available for timeline and process investigation.

The next investigation step is to inspect the complete Event ID 1 fields rather than relying only on the abbreviated PowerShell output.

---

## 10. Sysmon Event ID 7 Returned No Matching Event

The following query was used:

    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object {
        $_.Id -eq 7 -and
        $_.Message -match "DLLHijackLab"
    } |
    Select-Object TimeCreated,Message

Result:

    No matching event returned

### Possible Reasons

Several explanations are possible:

- Sysmon Image Load monitoring may not be enabled.
- The current Sysmon configuration may exclude the relevant event.
- Event ID 7 may not contain the expected path.
- The DLL loading mechanism may not generate the expected native Image Load telemetry.
- The query may not match the actual event fields.
- The activity may not have produced a native DLL Image Load event.

### Correct Investigation Approach

Do not assume which explanation is correct.

Instead, validate the Sysmon configuration and inspect Event ID 7 telemetry independently.

---

## 11. Check Whether Event ID 7 Exists

A broader Event ID 7 query can be used:

    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object {$_.Id -eq 7} |
    Select-Object -First 20 TimeCreated,Id,Message

If events are returned, inspect their structure.

If no events are returned at all, investigate whether Image Load monitoring is enabled in the Sysmon configuration.

---

## 12. Inspect Sysmon Configuration

The active Sysmon configuration can be reviewed with:

    sysmon64.exe -c

This helps determine whether Image Load monitoring is configured.

If the configuration does not include Image Load monitoring, Event ID 7 may not be generated.

---

## 13. Wazuh Search Limitation

A simple search for:

    DLLHijackLab

may not return results depending on the current Wazuh decoder and field structure.

The correct field names should therefore be confirmed from an actual Wazuh event.

Useful Event IDs for investigation are:

    11 - File Creation
    1  - Process Creation
    7  - Image Load

Avoid assuming that every Sysmon XML field is exposed under the same Wazuh field name.

---

## 14. Evidence Gap

The most important limitation in this exercise was the lack of a matching Event ID 7 Image Load event.

The investigation therefore has:

    File creation evidence: Confirmed
    Process creation telemetry: Available
    DLL loading through PowerShell: Confirmed
    Image Load telemetry: Not observed

This prevents the analyst from independently proving that the DLL was loaded through native Windows DLL search-order behavior.

---

## 15. Important Correction

The exercise initially targeted DLL Search Order Hijacking.

However, the actual loading mechanism used:

    [System.Reflection.Assembly]::LoadFrom()

This is explicit path-based .NET assembly loading.

It should therefore not be represented as confirmed native DLL Search Order Hijacking.

The repository documentation should clearly distinguish:

    Controlled DLL Loading

from:

    Confirmed DLL Search Order Hijacking

This distinction prevents overclaiming in the portfolio.

---

## 16. Recommended Next Improvement

A future version of the lab can use a controlled native Windows test executable that requests a DLL by filename rather than explicitly specifying the DLL path.

The investigation can then focus on:

    Legitimate Test Application
            ↓
    DLL Requested by Name
            ↓
    Windows DLL Search
            ↓
    Unexpected DLL Location
            ↓
    Image Load Telemetry
            ↓
    Wazuh Investigation

That would provide a more accurate demonstration of T1574.001.

---

## 17. Troubleshooting Principle

The main troubleshooting lesson from this lab is:

> A missing event is a telemetry problem to investigate, not permission to invent evidence.

The correct SOC workflow is:

    Observe
        ↓
    Validate
        ↓
    Correlate
        ↓
    Identify evidence gaps
        ↓
    Assess confidence
        ↓
    Report only what the evidence supports
