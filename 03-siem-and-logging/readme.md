<div align="center">

# 📊 03 - SIEM & Logging
**If it's not logged, it didn't happen. If you can't query it, the log is useless.**

[![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-orange?style=flat-square)](https://github.com/Ashiii27/soc-resources)
[![Role](https://img.shields.io/badge/Role-SOC%20Analyst%20%7C%20Detection%20Engineer-blue?style=flat-square)](https://github.com/Ashiii27/soc-resources)
[![Status](https://img.shields.io/badge/Status-In%20Progress-yellow?style=flat-square)](https://github.com/Ashiii27/soc-resources)

</div>

---

## 🎯 Module Objective
A SIEM is only as good as the logs feeding it and the rules running against it. This module teaches you to **collect, normalize, correlate, and query** security logs across enterprise environments — turning raw telemetry into security decisions.

---

## 🗺️ The SIEM & Logging Roadmap

### 1. 📥 Log Sources: What to Collect
*You can't detect what you don't log.*
- [ ] **Windows Event Logs**: Security (4624, 4625, 4688, 4698, 4720), System, PowerShell (4104), Sysmon.
- [ ] **Linux Logs**: `/var/log/auth.log`, `/var/log/syslog`, `/var/log/audit/audit.log` (auditd).
- [ ] **Firewall & Network**: Allow/deny logs, NAT translations, VPN connections.
- [ ] **DNS Logs**: Queries, responses, NXDomain rates — critical for detecting C2 beaconing.
- [ ] **Proxy / Web Logs**: URLs accessed, user-agents, response codes — spot web shell activity.
- [ ] **EDR Telemetry**: Process creation, file writes, registry changes, network connections.
- [ ] **Cloud Logs**: AWS CloudTrail, Azure Activity Logs, GCP Cloud Audit Logs.
- [ ] **Authentication**: Active Directory events, SSO, MFA logs.

### 2. 🔄 Log Normalization & Enrichment
*Raw logs are messy. Normalized logs are searchable.*
- [ ] **Common Event Format (CEF)**: A standardized log format used across SIEMs.
- [ ] **JSON Logging**: The modern standard — structured, queryable, parseable.
- [ ] **Field Extraction**: Parsing raw text into named fields (src_ip, dest_port, username).
- [ ] **Enrichment**: Appending context to raw events — GeoIP, threat intel lookups, asset database joins.
- [ ] **Normalization**: Mapping vendor-specific field names to a common schema (e.g., Elastic Common Schema, OCSF).

### 3. 🔍 Splunk SPL (Search Processing Language)
*The industry-standard SIEM query language.*
- [ ] **Basic Searching**: `index=windows EventCode=4625 | stats count by src_ip`
- [ ] **Filtering & Piping**: `| where`, `| eval`, `| rename`, `| table`
- [ ] **Statistical Commands**: `stats`, `chart`, `timechart`, `top`, `rare`
- [ ] **Subsearches**: Correlating multiple event types in a single query.
- [ ] **Lookups**: Joining search results with CSV threat feeds or asset lists.
- [ ] **Alerts & Saved Searches**: Scheduling detection rules and configuring real-time alerting.
- [ ] **Common Detection Queries**:
  - Brute force: Failed logins (4625) → Success (4624) within 5 minutes on same host
  - Lateral movement: Logon type 3 (network) from unusual source hosts
  - Persistence: Scheduled task creation (4698) by non-system accounts

### 4. 🔍 Elastic KQL & EQL
*The open-source alternative powering many modern SIEMs.*
- [ ] **KQL Basics**: `event.code: 4625 AND winlog.event_data.LogonType: 3`
- [ ] **EQL (Event Query Language)**: Sequence-based detections — ideal for multi-step attack chains.
- [ ] **Elastic Common Schema (ECS)**: Standardized field naming across all Elastic data sources.
- [ ] **Kibana Dashboards**: Building analyst-facing dashboards for triage and monitoring.
- [ ] **Detection Rules**: Using Elastic's pre-built SIEM detection rules and customizing them.

### 5. ☁️ Microsoft Sentinel & KQL
*The cloud-native SIEM for Azure environments.*
- [ ] **KQL for Sentinel**: `SecurityEvent | where EventID == 4625 | summarize count() by Account`
- [ ] **Workbooks**: Visual dashboards for security monitoring.
- [ ] **Analytics Rules**: Scheduled, near-real-time, and ML-based detection rules.
- [ ] **Playbooks**: SOAR automation via Azure Logic Apps.
- [ ] **Connector Sources**: Azure AD, Defender for Endpoint, Office 365, AWS, Syslog.

### 6. 🔗 Correlation & Detection Logic
*The art of connecting dots across time and systems.*
- [ ] **Correlation Rules**: Chaining multiple events into a meaningful alert (e.g., Recon → Exploit → Exfil).
- [ ] **Thresholds & Baselines**: Setting dynamic thresholds to reduce false positives.
- [ ] **Risk-Based Alerting (RBA)**: Assigning risk scores to entities (users, hosts) rather than individual events.
- [ ] **False Positive Tuning**: Whitelisting known-good activity without creating detection blind spots.

---

## 📊 Critical Windows Event IDs Cheatsheet

| Event ID | Category | What It Means |
| :--- | :--- | :--- |
| **4624** | Logon | Successful logon (check Logon Type) |
| **4625** | Logon | Failed logon — brute force indicator |
| **4648** | Logon | Logon using explicit credentials — lateral movement indicator |
| **4688** | Process | New process created — command execution tracking |
| **4698** | Scheduled Task | Scheduled task created — persistence mechanism |
| **4720** | Account | New user account created |
| **4732** | Group | Member added to security-enabled local group |
| **7045** | Service | New service installed — persistence/malware indicator |
| **1102** | Audit Log | Security audit log cleared — attacker covering tracks |

---

## 🚀 Quick Start Learning Path

| Topic | Recommended Resource | Type |
| :--- | :--- | :--- |
| **Splunk Fundamentals** | [Splunk Free Training](https://www.splunk.com/en_us/training/free-courses.html) | Free Course |
| **Elastic SIEM** | [TryHackMe: Investigating with ELK 101](https://tryhackme.com) | Interactive Lab |
| **Sentinel KQL** | [Microsoft Learn: KQL](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/) | Documentation |
| **Windows Logging** | [Malware Archaeology Cheatsheets](https://www.malwarearchaeology.com/cheat-sheets) | Reference |

---

## 🛠️ Analyst's Toolset for SIEM & Logging

- **Splunk Enterprise/SIEM**: Industry-leading SIEM with powerful SPL query engine.
- **Elastic Stack (ELK)**: Open-source log aggregation and analysis platform.
- **Microsoft Sentinel**: Cloud-native SIEM for Azure/hybrid environments.
- **Graylog**: Open-source centralized log management.
- **Sysmon**: Windows system monitor for enriched endpoint telemetry.

---

> **💡 Analyst's Insight: Log Everything, Alert Selectively**
> The goal isn't to alert on every suspicious event — it's to have the data available when you need it. Collect broadly, normalize consistently, and alert with precision. A well-tuned SIEM has **high-fidelity alerts**, not high-volume alerts.

---

<div align="center">

**Previous:** $\leftarrow$ [02 - Threat Intelligence](./../02-threat-intelligence/) &nbsp;&nbsp; | &nbsp;&nbsp; **Next:** $\rightarrow$ [04 - Detection Engineering](./../04-detection-engineering/)

</div>
