# References

This project was built using publicly available security frameworks, Microsoft documentation, and security tooling. The following resources were referenced throughout the implementation, configuration, adversary simulation, detection development, and validation of the Microsoft Sentinel detection engineering workflow.

---

## MITRE ATT&CK Framework

The MITRE ATT&CK framework was used to select adversary techniques, map detections, and document ATT&CK IDs throughout this project.

- https://attack.mitre.org/

### MITRE ATT&CK – T1574.001 DLL Search Order Hijacking

The T1574.001 technique documentation was used to understand DLL search order hijacking, DLL side-loading behaviour, execution flow hijacking, and associated detection considerations.

- https://attack.mitre.org/techniques/T1574/001/

### MITRE ATT&CK – Detection Strategy for DLL Hijacking

MITRE's DLL hijacking detection strategy was referenced when developing detection logic around unexpected DLL loads from non-standard directories and correlating module-load telemetry with other endpoint activity.

- https://attack.mitre.org/detectionstrategies/DET0201/

---

## Atomic Red Team

Atomic Red Team was used to simulate MITRE ATT&CK techniques on the Windows endpoint and validate the resulting endpoint telemetry and Microsoft Sentinel detections.

- https://github.com/redcanaryco/atomic-red-team
- https://atomicredteam.io/

---

## Microsoft Sysinternals Sysmon

Microsoft Sysmon was used to generate endpoint telemetry for process creation, file creation, registry activity, network activity, DNS queries, file deletion, and image/module loading.

Particular emphasis was placed on Sysmon Event ID 7 (Image Load), which records DLL and executable image loading within processes and provides information such as the loading process, loaded image, hashes, and signature information.

- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events

---

## Sysmon Event ID 7 – Image Load

Sysmon Event ID 7 was central to the DLL Search Order Hijacking detection developed in this project.

The event was used to identify relationships between:

- Executing process (`Image`)
- Loaded module (`ImageLoaded`)
- DLL path
- File hash
- Digital signature information
- User context

The detection used this telemetry to identify DLLs loaded from locations outside expected Windows system directories.

- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events

---

## Microsoft Sentinel

Microsoft Sentinel was used as the SIEM platform for ingesting Sysmon telemetry, developing KQL detections, creating Analytics Rules, and validating generated alerts and incidents.

- https://learn.microsoft.com/en-us/azure/sentinel/

---

## Microsoft Sentinel Analytics Rules

Microsoft Sentinel Analytics Rules were used to operationalize validated KQL detection queries and generate alerts and incidents from matching endpoint telemetry.

The Analytics Rules documentation was referenced for query configuration, scheduling, severity, MITRE ATT&CK technique mapping, and alert generation.

- https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules

---

## Kusto Query Language (KQL)

Kusto Query Language was used to develop and validate detection logic within Microsoft Sentinel.

KQL was used to filter Sysmon events, parse XML-based event data, extract fields, identify suspicious DLL loading behaviour, and correlate endpoint activity.

- https://learn.microsoft.com/en-us/kusto/query/
- https://learn.microsoft.com/en-us/kusto/query/tutorials/common-tasks-microsoft-sentinel
- https://learn.microsoft.com/en-us/kusto/query/kql-quick-reference

---

## Microsoft Sentinel KQL Detection Development

Microsoft documentation for working with KQL in Microsoft Sentinel was used to develop detection queries and perform filtering, parsing, aggregation, and correlation of endpoint telemetry.

- https://learn.microsoft.com/en-us/training/modules/work-with-data-kusto-query-language/

---

## Microsoft Windows Documentation

Microsoft Windows documentation was referenced to understand Windows process execution, DLL loading behaviour, system directories, and endpoint behaviour relevant to the simulated techniques.

- https://learn.microsoft.com/en-us/windows/

---

## Microsoft Windows Security Documentation

Microsoft Windows Security documentation was referenced for Windows security telemetry, endpoint monitoring, and security-related event information.

- https://learn.microsoft.com/en-us/windows/security/

---

## Sysinternals Suite

Microsoft Sysinternals documentation and utilities were used as part of the endpoint monitoring and investigation workflow.

- https://learn.microsoft.com/en-us/sysinternals/

---

## Acknowledgements

This project was developed as a hands-on purple team detection engineering exercise to understand adversary emulation, Windows endpoint telemetry, SIEM-based detection development, and security alert validation.

The project combines MITRE ATT&CK, Atomic Red Team, Sysmon, Kusto Query Language, and Microsoft Sentinel to demonstrate the detection engineering lifecycle from adversary simulation through telemetry analysis, detection development, Analytics Rule creation, and incident validation.
