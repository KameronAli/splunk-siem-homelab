# Project 02 — Windows Filtering Platform Detection (5156) + Auth Correlation

## Objective
Use **Windows Filtering Platform** telemetry (**Event ID 5156**) to detect network connections to sensitive services and correlate them with authentication failures (**4625**) for higher-confidence alerting.

## Lab Setup
- **Ubuntu**: Splunk Enterprise
- **Windows Server 2022**: log source (Security logs + Sysmon)
- **Kali Linux**: lab-only network/auth activity generation

## Telemetry Used
- **5156** — Windows Filtering Platform permitted a connection (network visibility)
- **4625** — Failed logon (auth failure signal)

Key fields observed in this dataset:
- `Destination_Port`, `Destination_Address`, `Direction`, `Application_Name`

---

## Detection 1 — RDP network connections (5156 on port 3389)
**Idea:** identify connections to RDP by filtering 5156 to destination port **3389**.

```spl
index=main sourcetype="WinEventLog:Security" EventCode=5156 Destination_Port=3389
| stats count AS connections values(Direction) AS direction values(Application_Name) AS applications by Destination_Address
| sort -connections
```
## Detection 2 — SMB network connections (5156 on port 445)
**Idea:** identify connections to RDP by filtering 5156 to destination port **3389**.

```spl
index=main sourcetype="WinEventLog:Security" EventCode=5156 Destination_Port=445
| stats count AS connections values(Direction) AS direction values(Application_Name) AS applications by Destination_Address
| sort -connections
```
## Detection 3 — Correlation: 5156 (RDP/SMB) + 4625 failures (same time window)
**Idea:** identify connections to RDP by filtering 5156 to destination port **3389**.

```spl
(
  index=main sourcetype="WinEventLog:Security" EventCode=5156 Destination_Port IN (3389,445)
  | eval service=if(Destination_Port==3389,"RDP","SMB")
  | bin _time span=5m
  | stats count AS net_events values(service) AS services by _time Destination_Address
)
| join type=left _time Destination_Address
[
  search index=main sourcetype="WinEventLog:Security" EventCode=4625
  | bin _time span=5m
  | stats count AS auth_fails by _time
]
| where net_events > 0 AND auth_fails >= 5
| table _time Destination_Address services net_events auth_fails
| sort -auth_fails
```

## Validation steps

Verified 5156 telemetry is ingested into Splunk.
Filtered 5156 events by service ports (3389/445).
Correlated time windows containing both service activity and repeated auth failures.
Captured evidence screenshots for each detection.

## MITRE ATT&CK Mapping

T1021 — Remote Services (RDP/SMB)
T1110 — Brute Force (failed logons)
