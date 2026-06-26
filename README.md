<div align="center">

```
███████╗ ██████╗  ██████╗    ██████╗ ███████╗███████╗ ██████╗ ██╗   ██╗██████╗  ██████╗███████╗███████╗
██╔════╝██╔═══██╗██╔════╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔════╝██╔════╝
███████╗██║   ██║██║         ██████╔╝█████╗  ███████╗██║   ██║██║   ██║██████╔╝██║     █████╗  ███████╗
╚════██║██║   ██║██║         ██╔══██╗██╔══╝  ╚════██║██║   ██║██║   ██║██╔══██╗██║     ██╔══╝  ╚════██║
███████║╚██████╔╝╚██████╗    ██║  ██║███████╗███████║╚██████╔╝╚██████╔╝██║  ██║╚██████╗███████╗███████║
╚══════╝ ╚═════╝  ╚═════╝    ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝
```

**A comprehensive, practitioner-built knowledge base for SOC analysts, blue teamers, and DFIR engineers.**

[![Maintained](https://img.shields.io/badge/Maintained-yes-brightgreen?style=flat-square)](https://github.com/Ashiii27/soc-blue-team-resources)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-blue?style=flat-square)](https://github.com/Ashiii27/soc-blue-team-resources/pulls)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-Top%202%25-red?style=flat-square&logo=tryhackme)](https://tryhackme.com)
[![GitHub](https://img.shields.io/badge/GitHub-Ashiii27-181717?style=flat-square&logo=github)](https://github.com/Ashiii27)

</div>

---

## Who this is for

This repo is built for people working in or moving toward defensive security — SOC analysts at any tier, blue team engineers, DFIR practitioners, and students building toward those roles. Everything here is organized around what you actually need on the job: detection logic, triage workflows, forensic methodology, and curated tooling — not a dumped list of links.

---

## What's inside

```
soc-blue-team-resources/
│
├── 01-fundamentals/              # Networking, OS internals, core security concepts
├── 02-threat-intelligence/       # MITRE ATT&CK, feeds, IOC lifecycle, threat actors
├── 03-siem-and-logging/          # Splunk SPL, Elastic KQL, Sentinel, log sources
├── 04-detection-engineering/     # Sigma rules, YARA rules, detection-as-code
├── 05-incident-response/         # Playbooks, triage, IR methodology (PICERL/SANS)
├── 06-digital-forensics/         # Windows + Linux + network forensics, artifacts
├── 07-malware-analysis/          # Static, dynamic, sandbox analysis, PE internals
├── 08-network-security/          # IDS/IPS, DNS, firewall, traffic pattern analysis
├── 09-vulnerability-management/  # CVE/CVSS/EPSS, scanning, patch workflows
├── 10-cloud-security/            # AWS, Azure, GCP security + cloud IR checklists
├── 11-threat-hunting/            # Hypothesis-driven hunting, hunt queries by TTP
├── 12-tools-and-automation/      # Blue team toolkit, Python scripts, automation
├── 13-certifications-and-learning/ # Roadmaps, platforms, rooms, books
├── 14-interview-prep/            # SOC, DFIR, detection engineering Q&A
└── resources/                    # Cheatsheets and templates
```

---

## Featured projects

These are real tools built alongside this repo. Each is linked from the relevant section.

| Project | What it does | Section |
|---|---|---|
| [SentinelX](https://github.com/Ashiii27/SentinelX) | C++ network IDS using libpcap with MITRE ATT&CK-tagged alerts | Network Security |
| [Windows Login Forensics](https://github.com/Ashiii27/windows-login-forensics) | Python + PowerShell EVTX parser for login event analysis | Digital Forensics |
| [PCAP Forensics Analyser](https://github.com/Ashiii27/pcap-forensics-analyser) | Network capture analysis and IOC extraction | Network Forensics |
| [CVE Explorer](https://github.com/Ashiii27/cve-explorer) | Full-stack vulnerability dashboard — FastAPI + React | Vulnerability Management |
| [cybersec-automation-scripts](https://github.com/Ashiii27/cybersec-automation-scripts) | Recon, detection, and IR automation scripts in Python/Bash | Tools & Automation |

---

## Quick reference

If you need something fast:

- **Investigating an alert right now?** → [IR Playbooks](05-incident-response/ir-playbooks/) · [Triage Checklist](05-incident-response/triage-checklist.md)
- **Writing a detection?** → [Sigma Rules](04-detection-engineering/sigma-rules/) · [SPL Queries](03-siem-and-logging/splunk/detection-queries.md) · [KQL Queries](03-siem-and-logging/elastic-siem/detection-queries.md)
- **Analyzing a Windows artifact?** → [Windows Forensics](06-digital-forensics/windows-forensics/) · [EVTX Analysis](06-digital-forensics/windows-forensics/evtx-log-analysis.md)
- **Analyzing a PCAP?** → [Network Forensics](06-digital-forensics/network-forensics/) · [Wireshark Cheatsheet](06-digital-forensics/network-forensics/wireshark-cheatsheet.md)
- **Prepping for interviews?** → [Interview Prep](14-interview-prep/) · [Scenario Questions](14-interview-prep/scenario-based-questions.md)
- **Choosing a cert?** → [Certification Roadmap](13-certifications-and-learning/certification-roadmap.md)

---

## Recommended learning path

This isn't the only path, but it's the one this repo is structured around — from analyst fundamentals to detection engineering to specialized offensive-defensive overlap:

```
Fundamentals → Threat Intel → SIEM & Logging → Detection Engineering
      ↓
Incident Response → Digital Forensics → Malware Analysis
      ↓
Network Security → Cloud Security → Threat Hunting
      ↓
Certifications: PNPT → CPTS → CRTP → CRTO → OSCP
```

---

## Coverage by role

| Role | Primary sections |
|---|---|
| SOC Analyst (Tier 1/2) | Fundamentals, SIEM & Logging, IR Playbooks, Triage, Interview Prep |
| Detection Engineer | Detection Engineering, Threat Intel, SIEM, Sigma/YARA |
| DFIR Analyst | Digital Forensics, Malware Analysis, IR Methodology, Evidence Collection |
| Threat Hunter | Threat Hunting, Threat Intel, MITRE ATT&CK, Hunt Queries |
| Blue Team Engineer | All sections — this repo is built for you |

---

## Contributing

Contributions are welcome — corrections, new playbooks, detection rules, or additional tooling references.

1. Fork the repo
2. Create a branch: `git checkout -b add/your-contribution`
3. Follow the existing document structure and formatting style
4. Submit a pull request with a clear description

For Sigma or YARA rule submissions, include a brief note on what the rule detects and the log source it targets.

---

## About

Built and maintained by [Ash](https://github.com/Ashiii27) — CSE undergrad, cybersecurity practitioner, TryHackMe Top 2%, and blue team enthusiast. This repo is a living document, updated as tools evolve, new techniques emerge, and better resources surface.

Connect: [GitHub](https://github.com/Ashiii27) · [LinkedIn](https://www.linkedin.com/in/ashiii27/) · [Medium](https://medium.com/@ashiii.2790)

---

<div align="center">

*If this helped you land a role, pass a cert, or catch a threat — drop a ⭐*

</div>
