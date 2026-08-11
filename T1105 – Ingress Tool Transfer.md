# T1105 – Ingress Tool Transfer

## Overview

Ingress Tool Transfer (T1105) is used by attackers to transfer tools, payloads, or other files from an external or remote location onto a compromised system. Attackers commonly use utilities such as PowerShell, `Invoke-WebRequest`, `curl`, or other network-capable tools to download files during post-compromise activity.

This detection demonstrates how ingress tool transfer activity can be identified using Sysmon endpoint telemetry and validated within Microsoft Sentinel after simulating attacker behaviour with Atomic Red Team.

---

## MITRE ATT&CK

| Field | Value |
|--------|-------|
| Technique ID | T1105 |
| Technique | Ingress Tool Transfer |
| Tactic | Command and Control |

---

## Detection Objective

The objective of this detection is to identify suspicious file transfer activity associated with PowerShell-based downloads on a Windows endpoint.

Attackers may use PowerShell to retrieve files from remote locations and write them to the local filesystem. Monitoring process creation and newly created files can therefore provide visibility into potential ingress tool transfer activity.

The detection focuses on PowerShell execution associated with file download activity and validates the resulting endpoint telemetry within Microsoft Sentinel.

---

## Attack Simulation

The Atomic Red Team framework was used to simulate Ingress Tool Transfer on the Windows victim endpoint.

The Atomic Red Team T1105 test was executed on the endpoint to generate file transfer activity.

```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"

Invoke-AtomicTest T1105
``` 
## Expected Result

PowerShell or another transfer utility is executed.
A file is retrieved from a remote location.
The downloaded file is written to the Windows endpoint.
Sysmon generates endpoint telemetry.
Microsoft Sentinel ingests the generated telemetry.
The detection query identifies the simulated transfer activity.
The validated detection can be implemented as a Microsoft Sentinel Analytics Rule.
Telemetry Generated
Source	Event
Sysmon	Event ID 1 – Process Creation
Sysmon	Event ID 11 – File Creation

Sysmon Process Creation (Event ID 1) provides visibility into the process responsible for the transfer, including the executable, command line, parent process, and user.

Sysmon File Creation (Event ID 11) provides visibility into files created on the endpoint following the transfer activity.

The combination of these events provides useful context for identifying files downloaded through PowerShell or other transfer utilities.

## Detection Query
```KQL 
Event
| where Computer == "SC200-Victim01"
| where EventID == 11
| where TimeGenerated > ago(5m)
| extend ParsedXML = parse_xml(EventData)
| mv-expand Data = ParsedXML.DataItem.EventData.Data
| extend
    FieldName = tostring(Data["@Name"]),
    FieldValue = tostring(Data["#text"])
| summarize
    Fields = make_bag(pack(FieldName, FieldValue))
    by TimeGenerated, EventID
| project
    TimeGenerated,
    EventID,
    Image = tostring(Fields.Image),
    TargetFilename = tostring(Fields.TargetFilename),
    User = tostring(Fields.User)
| where Image endswith @"\wsmprovhost.exe"
```
Detection Logic

The detection searches Sysmon Process Creation events for PowerShell processes associated with common file-transfer commands.

The query parses the XML contained within the EventData field because the required Sysmon fields were not directly exposed as individual Microsoft Sentinel columns.

The following fields are extracted:

User
Process Image
Command Line
Parent Process
Parent Command Line

The detection then looks for PowerShell execution containing indicators associated with file-transfer activity, including:

Invoke-WebRequest
iwr
Start-BitsTransfer
DownloadFile
WebClient
curl
wget

These indicators provide context that PowerShell may be performing an ingress tool transfer rather than simply executing a normal administrative command.

Detection Validation

The detection was validated against telemetry generated during the Atomic Red Team T1105 simulation.

Validation confirmed:

PowerShell execution associated with the transfer activity.
Command-line information was captured.
The executing user was identified.
The parent process was available.
File creation telemetry was generated where applicable.
The resulting Sysmon telemetry was ingested into Microsoft Sentinel.
KQL queries could identify the simulated activity.
Evidence
Attack Simulation Evidence

The Atomic Red Team T1105 test was executed on the Windows victim endpoint.

<img width="1112" height="756" alt="T1105 - ingress attacker execution" src="https://github.com/user-attachments/assets/563403f4-630e-4c93-921f-1d4d7f3a20a0" />

File process creation evidence
<img width="1115" height="740" alt="T1105 - ingress file appeared in the victim vm" src="https://github.com/user-attachments/assets/4b91c38a-2203-4406-b5ef-7eb6f64952e7" />

Sentinel Incident alert triggered evidence,

<img width="1907" height="875" alt="T1105 - ingress incident alert" src="https://github.com/user-attachments/assets/4ac97631-6de2-40d2-a125-1f60eb1a4e7b" />

Detection Query Validation

The KQL detection successfully identified PowerShell activity associated with ingress tool transfer.

## Microsoft Sentinel Analytics Rule

After validating the detection query against the generated telemetry, the detection was implemented as a Microsoft Sentinel Analytics Rule.
The rule was configured to monitor for PowerShell-based file transfer activity and generate an alert when the detection logic matched endpoint telemetry.

The detection was mapped to:

T1105 – Ingress Tool Transfer
The Analytics Rule provides an operational detection layer within Microsoft Sentinel rather than relying solely on manual KQL investigation.

## Outcome

This detection successfully demonstrated the identification of ingress tool transfer activity using Sysmon endpoint telemetry and Microsoft Sentinel.
The simulation generated PowerShell-based transfer activity on the Windows endpoint. Sysmon captured the resulting process execution and file activity, while Microsoft Sentinel provided the telemetry analysis and detection layer.
A custom KQL query was developed to parse Sysmon XML data, extract process and command-line information, and identify PowerShell activity associated with common file-transfer mechanisms.

The detection demonstrates the purple team workflow:

Adversary simulation using Atomic Red Team
Endpoint telemetry generation using Sysmon
Sysmon Event ID 1 analysis
Sysmon Event ID 11 analysis
KQL detection development
Microsoft Sentinel Analytics Rule creation
Detection validation
MITRE ATT&CK mapping
