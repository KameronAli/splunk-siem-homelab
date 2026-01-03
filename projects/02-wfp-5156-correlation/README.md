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
index=main sourcetype="WinEventLog:Security" (EventCode=5156 OR EventCode=4625)
| eval dest=Destination_Address
| eval dest_port=Destination_Port
| eval service=case(dest_port==3389,"RDP", dest_port==445,"SMB", true(), null())
| where (EventCode=5156 AND dest_port IN (3389,445)) OR EventCode=4625
| bin _time span=5m
| stats
    count(eval(EventCode=4625)) AS auth_fails
    count(eval(EventCode=5156 AND dest_port==3389)) AS rdp_net
    count(eval(EventCode=5156 AND dest_port==445)) AS smb_net
    values(service) AS services
    values(dest) AS destinations
  by _time
| where auth_fails >= 5 AND (rdp_net > 0 OR smb_net > 0)
| table _time auth_fails rdp_net smb_net services destinations
| sort -auth_fails,,
```

## Validation steps

Verified 5156 telemetry is ingested into Splunk.
Filtered 5156 events by service ports (3389/445).
Correlated time windows containing both service activity and repeated auth failures.
Captured evidence screenshots for each detection.

## MITRE ATT&CK Mapping

T1021 — Remote Services (RDP/SMB)
T1110 — Brute Force (failed logons)

## Evidence (Screenshots)

**Detection 1 — 5156 RDP (3389)**
![5156 RDP 3389](https://github.com/KameronHuggins/splunk-siem-homelab/blob/main/projects/02-wfp-5156-correlation/screenshots/5156-rdp-3389.png)

**Detection 2 — 5156 SMB (445)**
![5156 SMB 445](https://github.com/KameronHuggins/splunk-siem-homelab/blob/main/projects/02-wfp-5156-correlation/screenshots/5156-smb-445.png)

**Detection 3 — Correlation (5156 + 4625)**
![5156 + 4625 correlation](https://github.com/KameronHuggins/splunk-siem-homelab/blob/main/projects/02-wfp-5156-correlation/screenshots/5156-4625-correlation.png)

