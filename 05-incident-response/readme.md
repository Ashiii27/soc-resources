<div align="center">

# 🚨 05 - Incident Response
**Speed is nothing without process. Process is nothing without speed.**

[![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-orange?style=flat-square)](https://github.com/Ashiii27/soc-resources)
[![Role](https://img.shields.io/badge/Role-L2%20Analyst%20%7C%20IR%20Engineer-blue?style=flat-square)](https://github.com/Ashiii27/soc-resources)
[![Status](https://img.shields.io/badge/Status-In%20Progress-yellow?style=flat-square)](https://github.com/Ashiii27/soc-resources)

</div>

---

## 🎯 Module Objective
Incident Response (IR) is the **structured process of detecting, containing, eradicating, and recovering from security incidents**. This module covers the frameworks, playbooks, triage methodologies, and documentation practices used by professional IR teams.

---

## 🗺️ The Incident Response Roadmap

### 1. 📋 IR Frameworks
*The playbook behind the playbooks.*

#### NIST SP 800-61 (The Standard)
- [ ] **Preparation**: Policies, tools, team training, playbook development.
- [ ] **Detection & Analysis**: Identifying incidents from alerts, logs, and threat intel.
- [ ] **Containment, Eradication & Recovery**: Stopping the spread, removing the threat, restoring systems.
- [ ] **Post-Incident Activity**: Lessons learned, root cause analysis, control improvements.

#### PICERL (Practitioner Favourite)
- [ ] **Preparation** → **Identification** → **Containment** → **Eradication** → **Recovery** → **Lessons Learned**

#### SANS IR Process
- [ ] **Preparation** → **Identification** → **Containment** → **Eradication** → **Recovery** → **Follow-Up**

### 2. 🔍 Incident Identification & Triage
*The first 15 minutes matter most.*
- [ ] **Alert Triage**: Is this a True Positive or False Positive? Use enrichment data to decide fast.
- [ ] **Incident Severity Classification**:
  - **P1 (Critical)**: Active breach, ransomware, data exfiltration in progress.
  - **P2 (High)**: Confirmed compromise, lateral movement detected.
  - **P3 (Medium)**: Suspicious activity requiring investigation.
  - **P4 (Low)**: Policy violation, low-risk anomaly.
- [ ] **Scope Assessment**: How many systems are affected? What data is at risk?
- [ ] **Initial Evidence Collection**: Preserve volatile data first — running processes, network connections, memory.

### 3. 🔒 Containment Strategies
*Stop the bleeding before you treat the wound.*
- [ ] **Short-Term Containment**: Isolate infected host via EDR network isolation, firewall block.
- [ ] **Long-Term Containment**: Change credentials, segment VLAN, patch the exploited vulnerability.
- [ ] **Evidence Preservation**: Image the disk and capture memory **before** any remediation.
- [ ] **Communication**: Notify stakeholders — legal, HR, management — based on severity.

### 4. 🧹 Eradication
*Remove every trace of the adversary.*
- [ ] **Identify all affected systems**: Use SIEM to identify all hosts the attacker touched.
- [ ] **Remove malware and persistence mechanisms**: Scheduled tasks, registry Run keys, new user accounts, web shells.
- [ ] **Patch the vulnerability**: The root cause that enabled initial access.
- [ ] **Reset compromised credentials**: Every account the attacker had access to.

### 5. 🔄 Recovery
*Return to operations without re-infection.*
- [ ] **System Restoration**: Restore from clean backups or re-image affected systems.
- [ ] **Monitoring Enhancement**: Increase logging verbosity on recovered systems for 30+ days.
- [ ] **Phased Return**: Bring systems back online gradually, monitoring at each stage.
- [ ] **Validate Clean State**: Confirm no persistence mechanisms remain.

### 6. 📝 Post-Incident Activity
*The most important phase that gets skipped most often.*
- [ ] **Timeline Reconstruction**: Build a complete attacker timeline from first access to detection.
- [ ] **Root Cause Analysis (RCA)**: What was the initial vector? Why wasn't it detected sooner?
- [ ] **Lessons Learned Report**: Document findings for the whole team.
- [ ] **Control Improvements**: Update playbooks, detection rules, and security controls.

---

## 📋 IR Playbooks (Common Scenarios)

| Incident Type | Key Actions | Priority |
| :--- | :--- | :--- |
| **Phishing** | Quarantine email, analyse URL/attachment, check all recipients, reset credentials | P2 |
| **Ransomware** | Isolate host NOW, identify patient zero, check backups, engage response team | P1 |
| **Brute Force** | Block source IP, check for successful logins, reset account, enable MFA | P3 |
| **Insider Threat** | Preserve evidence before alerting, engage HR/Legal, review access logs | P2 |
| **Web Shell** | Take server offline, identify upload vector, remove shell, audit all files | P1 |
| **Data Exfiltration** | Block egress, identify exfiltrated data scope, engage legal | P1 |

---

## 🚀 Quick Start Learning Path

| Topic | Recommended Resource | Type |
| :--- | :--- | :--- |
| **IR Fundamentals** | [NIST SP 800-61](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) | Official Guide |
| **Practical IR** | [TryHackMe: Incident Response Room](https://tryhackme.com) | Interactive Lab |
| **Playbooks** | [CISA IR Playbooks](https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf) | Official Playbooks |
| **IR Automation** | [TheHive Project](https://thehive-project.org/) | Open Source Platform |

---

## 🛠️ Analyst's IR Toolkit

- **TheHive**: Open-source incident management and case tracking platform.
- **Velociraptor**: Digital forensics and incident response collection framework.
- **Volatility**: Memory forensics framework for extracting artifacts from RAM.
- **KAPE**: Rapid triage collection tool for Windows artifacts.
- **FTK Imager**: Disk imaging and evidence preservation tool.

---

> **💡 Analyst's Insight: Contain First, Investigate Second**
> The instinct of a new analyst is to investigate before containing. **Resist it.** Every minute an attacker is active, they are creating more damage, moving laterally, and escalating privileges. Isolate the host — you can always do forensics on an isolated machine.

---

<div align="center">

**Previous:** $\leftarrow$ [04 - Detection Engineering](./../04-detection-engineering/) &nbsp;&nbsp; | &nbsp;&nbsp; **Next:** $\rightarrow$ [06 - Digital Forensics](./../06-digital-forensics/)

</div>
