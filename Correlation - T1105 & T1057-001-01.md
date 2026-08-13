# T1105 + T1547.001 – Correlated Behavioral Sequence

## Overview

This detection demonstrates a **correlated behavioral sequence** in Microsoft Sentinel combining:

* **T1105 – Ingress Tool Transfer**
* **T1547.001 – Registry Run Keys / Startup Folder**

The objective is to identify a sequence where activity associated with **`wsmprovhost.exe`**, commonly associated with Windows Remote Management (WinRM), is followed by a modification to the Windows **Run registry key** within a defined time window.

Rather than alerting independently on each event, the detection correlates the two behaviors on the same host and user.

This increases confidence that the activity represents a post-compromise execution and persistence sequence rather than an isolated administrative action.

---

## MITRE ATT&CK

| Technique | Name                               | Role in Detection                                                        |
| --------- | ---------------------------------- | ------------------------------------------------------------------------ |
| T1105     | Ingress Tool Transfer              | File creation associated with remote execution through `wsmprovhost.exe` |
| T1547.001 | Registry Run Keys / Startup Folder | Modification of the Windows `Run` registry key                           |

### Behavioral Sequence

```text
Remote execution / staging
        │
        ▼
wsmprovhost.exe
        │
        ▼
File creation on victim
        │
        │  within 15 minutes
        ▼
Registry Run Key modification
        │
        ▼
T1547.001 persistence
        │
        ▼
HIGH-CONFIDENCE CORRELATED ALERT
```

---

## Lab Environment

**Victim**

```text
SC200-Victim01
```

**Attacker**

```text
SC200-Attacker01
```

**Telemetry**

```text
Sysmon
Microsoft Sentinel
Microsoft Defender
```

The Sysmon configuration was used to collect the relevant process, file, and registry telemetry.

The relevant Sysmon events for this detection were:

* **Event ID 11** – File Create
* **Event ID 13** – Registry Value Set

---

## Detection Logic

The first portion of the query identifies file creation events where the creating image is:

```text
C:\Windows\System32\wsmprovhost.exe
```

This provides the remote-execution/staging side of the behavioral sequence.

The second portion identifies registry modifications targeting:

```text
\Software\Microsoft\Windows\CurrentVersion\Run\
```

The two event streams are then joined using:

* Computer
* User

The registry modification must occur **after** the file creation event and within **15 minutes**.

---

## KQL

```kusto
Event
| where Computer == "SC200-Victim01"
| where EventID == 11
| where TimeGenerated > ago(30m)
| extend ParsedXML = parse_xml(EventData)
| mv-expand Data = ParsedXML.DataItem.EventData.Data
| extend
    FieldName = tostring(Data["@Name"]),
    FieldValue = tostring(Data["#text"])
| summarize
    Fields = make_bag(pack(FieldName, FieldValue))
    by TimeGenerated, EventID, Computer
| project
    T1105Time = TimeGenerated,
    Computer,
    User = tostring(Fields.User),
    T1105Image = tostring(Fields.Image),
    TargetFilename = tostring(Fields.TargetFilename)
| where T1105Image endswith @"\wsmprovhost.exe"
| join kind=inner (
    Event
    | where Computer == "SC200-Victim01"
    | where EventID == 13
    | where TimeGenerated > ago(30m)
    | extend ParsedXML = parse_xml(EventData)
    | mv-expand Data = ParsedXML.DataItem.EventData.Data
    | extend
        FieldName = tostring(Data["@Name"]),
        FieldValue = tostring(Data["#text"])
    | summarize
        Fields = make_bag(pack(FieldName, FieldValue))
        by TimeGenerated, EventID, Computer
    | project
        T1547Time = TimeGenerated,
        Computer,
        User = tostring(Fields.User),
        T1547Image = tostring(Fields.Image),
        TargetObject = tostring(Fields.TargetObject),
        Details = tostring(Fields.Details)
    | where TargetObject has @"\Software\Microsoft\Windows\CurrentVersion\Run\"
) on Computer, User
| where T1547Time >= T1105Time
| where T1547Time <= T1105Time + 15m
| project
    T1105Time,
    T1547Time,
    Computer,
    User,
    T1105Image,
    TargetFilename,
    T1547Image,
    TargetObject,
    Details
| order by T1105Time desc
```

---

## Why Correlation?

A single file creation event is not necessarily malicious.

Likewise, a Run-key modification can have legitimate administrative or software-installation causes.

The detection instead asks:

> **Did activity associated with `wsmprovhost.exe` create a file, followed shortly afterward by a Run-key modification by the same user on the same machine?**

This behavioral relationship is considerably more interesting than either event in isolation.

The detection therefore uses **temporal correlation** rather than relying solely on a single indicator.

---

## Attack Execution

The test was executed remotely against the victim system.

The attacker used PowerShell remoting to reach the victim:

```powershell
Invoke-Command -ComputerName 10.0.1.4 -Credential $cred -ScriptBlock {
    ...
}
```

The activity resulted in telemetry generated by the Windows Remote Management execution path.

On the victim, Sysmon recorded activity associated with:

```text
C:\Windows\System32\wsmprovhost.exe
```

This provided the process context used by the correlation query.

---

## Registry Persistence Activity

The test subsequently created a Run-key entry.

The registry location observed in the telemetry was:

```text
HKU\S-1-5-21-...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
```

The associated details referenced:

```text
C:\Path\AtomicRedTeam.exe
```

This demonstrated the persistence component represented by **T1547.001**.

---

## Validation

The detection was validated at multiple stages.

### 1. Analytics Rule

The Microsoft Sentinel Analytics Rule was configured as:

```text
Correlation - T1105 + T1547.001
```

The rule was configured with:

* **Severity:** High
* **Status:** Enabled
* **Rule frequency:** Every 5 minutes
* **Rule period:** Last 5 minutes
* **Threshold:** More than 0 results
* **Event grouping:** Group all events into a single alert

The rule was successfully deployed and enabled.

---

### 2. Sysmon Confirmation

The victim host confirmed the underlying telemetry.

Relevant Sysmon events included:

```text
Event ID 11 — File created
Event ID 13 — Registry value set
```

The events could also be retrieved directly from:

```text
Microsoft-Windows-Sysmon/Operational
```

This provided host-level confirmation that Sentinel was receiving the expected telemetry.

---

### 3. Sentinel Correlation

The correlation query successfully produced a result containing fields including:

```text
T1105Time
T1547Time
Computer
User
T1105Image
TargetFilename
T1547Image
TargetObject
Details
```

The observed sequence showed:

```text
wsmprovhost.exe
        ↓
file creation
        ↓
Run-key modification
```

with the events occurring within the configured 15-minute correlation window.

---

### 4. Sentinel Incident

Microsoft Sentinel generated a **High severity incident**:

```text
Correlation - T1105 + T1547.001
```

The incident contained the correlated event data and exposed the relationship between the remote execution/staging activity and the subsequent persistence behavior.

This represents the final validation point of the detection pipeline:

```text
Endpoint activity
      ↓
Sysmon telemetry
      ↓
Log ingestion
      ↓
KQL correlation
      ↓
Analytics Rule
      ↓
Sentinel Alert
      ↓
Sentinel Incident
```

---

## Detection Output

The resulting incident provided contextual fields such as:

```text
Computer:
SC200-Victim01

User:
SC200-Victim01\sc200admin

T1105Image:
C:\Windows\System32\wsmprovhost.exe

TargetFilename:
C:\Users\sc200admin\AppData\Local\Temp\...

T1547Image:
C:\Windows\System32\reg.exe

TargetObject:
HKU\...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\...

Details:
C:\Path\AtomicRedTeam.exe
```

The exact values may vary between executions depending on the generated temporary files, process IDs, timestamps, and test artifacts.

---

## Screenshots

### Analytics Rule

The configured Microsoft Sentinel Analytics Rule:

<img width="1902" height="892" alt="analytics rule in place" src="https://github.com/user-attachments/assets/f7306795-8c74-40a8-84b6-13c2c1bb2244" />

### Attacker Execution

Remote execution from the attacker VM:

<img width="1877" height="982" alt="Attacker execution" src="https://github.com/user-attachments/assets/72f0f222-6e68-4786-a3a7-bcdaeb443aee" />

### Sysmon Confirmation

Host-level confirmation of the relevant Sysmon events:

<img width="1897" height="1000" alt="Sysmon confirmation on victim vm" src="https://github.com/user-attachments/assets/5566a5a3-4111-4d13-99c4-c39cc5615cfa" />

### Sentinel Correlation Incident

The resulting Sentinel incident showing the correlated behavioral sequence:

<img width="1907" height="871" alt="correlation incident 🗣️🗣️" src="https://github.com/user-attachments/assets/01dda74e-e96c-4ff0-8f82-5cf1ef5645e2" />

---

## Detection Strengths

### Temporal correlation

The detection does not simply search for two unrelated events. It requires the persistence event to occur after the initial activity and within a defined window:

```text
T1547Time >= T1105Time
```

and:

```text
T1547Time <= T1105Time + 15m
```

### Host correlation

The events must originate from the same:

```text
Computer
```

### User correlation

The events are additionally correlated on:

```text
User
```

This helps associate the behaviors with the same execution context.

### Behavioral detection

The detection focuses on an **attack sequence** rather than a static filename or hash.

---

## False Positive Considerations

Legitimate remote administration can generate `wsmprovhost.exe` activity.

Legitimate software installation or administrative configuration can also modify Run keys.

Therefore, neither behavior should automatically be considered malicious in isolation.

The correlation is intended to increase confidence by identifying the combination of:

```text
Remote execution/staging
+
File creation
+
Run-key persistence
+
Same host
+
Same user
+
Short time window
```

Additional environmental tuning may be appropriate in a production environment.

Potential tuning candidates include:

* Approved administrative accounts
* Known management systems
* Approved software installers
* Known deployment tooling
* Trusted automation accounts

---

## Investigation Workflow

When this alert fires, an analyst can investigate in the following order:

1. Identify the affected host.
2. Identify the user associated with the activity.
3. Review the `wsmprovhost.exe` activity.
4. Examine the created file and its location.
5. Review the Run-key modification.
6. Determine what executable or command was configured for persistence.
7. Review surrounding Sysmon Event ID 1 process creation events.
8. Review network and PowerShell telemetry surrounding the same timestamp.
9. Determine whether the initiating account and remote source were expected.
10. Escalate if the activity cannot be attributed to legitimate administration.

---

## Key Takeaway

The main objective of this detection is not simply to detect `wsmprovhost.exe` or a Run-key modification.

It demonstrates how **Microsoft Sentinel can correlate multiple low-to-medium confidence endpoint behaviors into a higher-confidence detection**.

The resulting behavioral chain is:

```text
Remote execution
      ↓
wsmprovhost.exe
      ↓
File creation / staging
      ↓
Run-key modification
      ↓
Persistence
      ↓
Correlated Sentinel incident
```

This approach provides more useful context to an analyst than treating each Sysmon event as an independent alert.

---

## Lab Result

**Detection status:** Validated

**Telemetry:** Confirmed

**Correlation:** Successful

**Sentinel Analytics Rule:** Enabled

**Incident generation:** Successful

**Severity:** High

**MITRE ATT&CK:** T1105 + T1547.001
The key learning outcome was understanding how endpoint telemetry can be joined across event types and constrained by **host, user, and time** to produce a higher-confidence security signal.
