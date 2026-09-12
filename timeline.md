# Timeline - DLL Search Order Hijacking Investigation

## Investigation Timeline

This timeline records the major activities performed during the controlled DLL loading investigation.

---

## 07:46 - Laboratory Directory Created

A dedicated directory was created for the investigation:

    C:\DLLHijackLab

PowerShell command:

    New-Item -ItemType Directory -Path C:\DLLHijackLab -Force

Purpose:

- Isolate the laboratory artifacts.
- Avoid modifying Windows system directories.
- Provide a predictable location for investigation.

---

## 07:48:12 - Test DLL Created

The controlled DLL was present at:

    C:\DLLHijackLab\TestLibrary.dll

File size:

    2560 bytes

Creation time:

    12 September 2026 07:48:12

Last write time:

    12 September 2026 07:48:12

---

## 07:48:12 - Sysmon Event ID 11 Observed

Sysmon recorded file creation activity involving the laboratory directory.

Event:

    Event ID 11 - File Create

Observed time:

    12-09-2026 07:48:12

Event metadata included:

    Computer: DESKTOP-9MMM37V
    Event ID: 11
    Event Record ID: 257687

This provides endpoint evidence that file creation activity was recorded.

---

## 07:48 - DLL Hash Recorded

SHA256 was calculated for the test DLL.

Hash:

    8423129446749C595A4AB5356B5B4EC454D8AE332161E00B5A229A28E1A208F8

The hash was recorded for artifact identification.

---

## 07:48 - Digital Signature Checked

The DLL was checked using PowerShell.

Result:

    Status: NotSigned

The unsigned status was recorded as an artifact characteristic.

---

## 07:51:59 - Process Creation Telemetry Available

Sysmon Event ID 1 process creation events were available around the investigation period.

Observed event range began approximately at:

    07:51:59

Event ID:

    1 - Process Create

---

## 07:52:06 - DLL Loading Activity

The DLL was loaded using:

    [System.Reflection.Assembly]::LoadFrom("C:\DLLHijackLab\TestLibrary.dll")

The test method was invoked successfully.

Observed output:

    DLL Hijack Lab test assembly loaded.

Execution time:

    12 September 2026 07:52:06

---

## 07:52 - Process Investigation

Multiple Sysmon Event ID 1 records were available around the DLL loading activity.

The process telemetry can be used to investigate:

- Process name
- Process path
- Parent process
- Parent Process ID
- Process ID
- Command line
- Execution time

---

## 07:53:02 - Latest Observed Process Creation Event

The Event ID 1 query returned process creation activity up to approximately:

    07:53:02

This establishes the available process telemetry window surrounding the test.

---

## Investigation Period - Event ID 7 Search

Sysmon Event ID 7 was searched for the laboratory directory.

Search condition:

    Event ID = 7
    Message contains DLLHijackLab

Result:

    No matching event returned

This became the primary telemetry gap in the investigation.

---

## Investigation Period - Wazuh Review

The laboratory indicator used for investigation was:

    DLLHijackLab

Relevant Sysmon events:

    Event ID 11 - File Creation
    Event ID 1  - Process Creation
    Event ID 7  - Image Load

Wazuh field names were treated as schema-dependent and were not assumed without validating actual event data.

---

## Final Timeline Assessment

The evidence establishes the following sequence:

    07:46
      ↓
    DLLHijackLab directory created
      ↓
    07:48:12
      ↓
    TestLibrary.dll created
      ↓
    07:48:12
      ↓
    Sysmon Event ID 11 recorded file creation
      ↓
    07:51:59+
      ↓
    Sysmon Event ID 1 process creation telemetry available
      ↓
    07:52:06
      ↓
    TestLibrary.dll loaded through PowerShell
      ↓
    07:53:02
      ↓
    Process creation telemetry still available
      ↓
    Event ID 7 search
      ↓
    No matching Image Load event observed

---

## Final Investigation Status

```text
File Creation: Confirmed
Process Creation Telemetry: Available
DLL Loading: Confirmed through PowerShell
Image Load Telemetry: Not Observed
Native DLL Search Order Hijacking: Not Confirmed
Investigation Status: Inconclusive
```

## Key Timeline Lesson

The timeline confirms that the DLL existed before the controlled loading activity and that endpoint telemetry was generated.

However, the available evidence does not establish the native Windows DLL search-order behavior required to confirm T1574.001.

> Follow the evidence, not the assumption.
