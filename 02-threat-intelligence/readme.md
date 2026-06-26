<div align="center">

# 🕵️ 02 - Threat Intelligence
**Know your enemy before they know your network.**

[![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-orange?style=flat-square)](https://github.com/Ashiii27/soc-resources)
[![Role](https://img.shields.io/badge/Role-All%20Blue%20Team-blue?style=flat-square)](https://github.com/Ashiii27/soc-resources)
[![Status](https://img.shields.io/badge/Status-In%20Progress-yellow?style=flat-square)](https://github.com/Ashiii27/soc-resources)

</div>

---

## 🎯 Module Objective
Threat Intelligence (CTI) transforms raw data into **actionable knowledge** about adversaries. In a SOC, CTI answers the three critical questions: **Who is attacking us? How are they doing it? What are they after?** This module covers the full intelligence lifecycle — from ingestion to operationalization.

---

## 🗺️ The Threat Intelligence Roadmap

### 1. 🧠 The Intelligence Lifecycle
*CTI is a process, not a product.*
- [ ] **Direction**: Define intelligence requirements — what does your organization need to know?
- [ ] **Collection**: Gather raw data from OSINT, dark web, ISACs, commercial feeds.
- [ ] **Processing**: Normalize and enrich raw data (IP reputation, domain whois, file hashes).
- [ ] **Analysis**: Turn processed data into intelligence (TTPs, actor profiling, campaign tracking).
- [ ] **Dissemination**: Deliver finished intelligence to the right teams (L1 IOC feeds, L3 threat reports).
- [ ] **Feedback**: Measure intelligence effectiveness and refine requirements.

### 2. 🎯 Intelligence Types
*Understanding the layers of CTI.*
- [ ] **Strategic CTI**: High-level, long-term. Nation-state actors, geopolitical risk, industry targeting trends. Audience: CISO, executives.
- [ ] **Operational CTI**: Campaign and actor-level. Upcoming attacks, TTPs of active threat groups. Audience: IR teams, L3 analysts.
- [ ] **Tactical CTI**: TTPs mapped to MITRE ATT&CK. How a specific actor achieves their objectives. Audience: Detection engineers.
- [ ] **Technical CTI**: Raw indicators — IPs, hashes, domains, URLs. Audience: L1 analysts, SIEM/firewall rules.

### 3. 🗓️ MITRE ATT&CK Framework
*The universal language of adversarial behaviour.*
- [ ] **Tactics**: The "why" — the adversary's high-level goal (e.g., Initial Access, Persistence, Exfiltration).
- [ ] **Techniques**: The "how" — the specific method used (e.g., T1566 Phishing, T1059 Command and Scripting Interpreter).
- [ ] **Sub-techniques**: Granular variants of techniques (e.g., T1059.001 PowerShell, T1059.003 Windows Command Shell).
- [ ] **Mitigations & Detections**: ATT&CK provides defensive mappings for each technique.
- [ ] **Groups & Software**: Real-world threat actor profiles (APT28, Lazarus Group) and malware families (Cobalt Strike, Mimikatz).

### 4. 📡 Indicator of Compromise (IOC) Lifecycle
*IOCs expire — adversaries pivot.*
- [ ] **Types**: IP addresses, domain names, file hashes (MD5/SHA256), URLs, email addresses, registry keys, mutexes.
- [ ] **The Pyramid of Pain**: Understanding why blocking hashes is easy but disrupting TTPs forces the adversary to retool.
- [ ] **IOC Scoring**: Assigning confidence levels and expiry dates to indicators.
- [ ] **Threat Feeds**: MISP, AlienVault OTX, Mandiant Advantage, Recorded Future, VirusTotal.

### 5. 👥 Threat Actor Profiling
*Building adversary dossiers.*
- [ ] **Attribution**: Nation-state (APTs), criminal groups (eCrime), hacktivists, insiders.
- [ ] **Motivations**: Financial, espionage, disruption, ideology.
- [ ] **TTPs**: Actor-specific techniques — e.g., APT29's use of supply chain compromises.
- [ ] **Diamond Model**: Mapping adversary, capability, infrastructure, and victim for campaign analysis.

---

## 📊 Key Frameworks & Models

| Framework | Purpose | Use Case |
| :--- | :--- | :--- |
| **MITRE ATT&CK** | Adversary behaviour taxonomy | Detection mapping, threat hunting |
| **Diamond Model** | Campaign relationship analysis | Intrusion attribution |
| **Pyramid of Pain** | Indicator value assessment | Prioritizing defensive controls |
| **Kill Chain** | Attack phase modelling | Identifying detection opportunities |
| **STIX/TAXII** | CTI data format & transport | Sharing intelligence between platforms |

---

## 🚀 Quick Start Learning Path

| Topic | Recommended Resource | Type |
| :--- | :--- | :--- |
| **MITRE ATT&CK** | [attack.mitre.org](https://attack.mitre.org) | Interactive Knowledge Base |
| **CTI Fundamentals** | [TryHackMe: Threat Intelligence Tools](https://tryhackme.com) | Interactive Lab |
| **Diamond Model** | [The Diamond Model Paper](https://www.activeresponse.org/the-diamond-model/) | Research Paper |
| **IOC Analysis** | [VirusTotal](https://www.virustotal.com) | Live Tool Practice |
| **Threat Feeds** | [AlienVault OTX](https://otx.alienvault.com) | Open Feed |

---

## 🛠️ Analyst's Toolset for Threat Intelligence

- **MISP**: Open-source threat intelligence sharing platform.
- **OpenCTI**: Structured CTI management and visualization.
- **VirusTotal**: Multi-engine hash, URL, and IP reputation lookups.
- **Shodan**: Adversary infrastructure discovery and pivoting.
- **MITRE ATT&CK Navigator**: Visual mapping of TTPs to defender coverage.

---

> **💡 Analyst's Insight: The Pyramid of Pain**
> Blocking an IP takes an attacker seconds to circumvent. Disrupting their TTPs forces them to rebuild their entire toolset. Always prioritize detections at the **TTP level** — your SIEM rules should trigger on *behaviour*, not just *indicators*.

---

<div align="center">

**Previous:** $\leftarrow$ [01 - Fundamentals](./../01-fundamentals/) &nbsp;&nbsp; | &nbsp;&nbsp; **Next:** $\rightarrow$ [03 - SIEM & Logging](./../03-siem-and-logging/)

</div>
