<div align="center">

# 🌐 01 - Security Fundamentals
**The bedrock of defensive security. You cannot defend what you do not understand.**

[![Difficulty](https://img.shields.io/badge/Difficulty-Beginner-green?style=flat-square)](https://github.com/Ashiii27/soc-blue-team-resources)
[![Role](https://img.shields.io/badge/Role-All%20Blue%20Team-blue?style=flat-square)](https://github.com/Ashiii27/soc-blue-team-resources)
[![Status](https://img.shields.io/badge/Status-In%20Progress-yellow?style=flat-square)](https://github.com/Ashiii27/soc-blue-team-resources)

</div>

---

## 🎯 Module Objective
The goal of this module is to transition you from a general IT understanding to a **security-centric mindset**. In a SOC, you aren't just looking for "errors"—you are looking for **adversarial intent** hidden within standard system behavior.

---

## 🗺️ The Fundamentals Roadmap

### 1. 🔌 Networking for Analysts
*If you can't read the wire, you're blind to the attack.*
- [ ] **The OSI Model**: Understanding encapsulation and where different attacks happen (e.g., Layer 2 ARP spoofing vs Layer 7 SQLi).
- [ ] **TCP/IP Suite**: Three-way handshake, flags (SYN, ACK, FIN, RST), and how to spot a port scan.
- [ ] **Core Protocols**: 
    - **DNS**: The "phonebook" of the internet (and the favorite tool for C2 beacons).
    - **HTTP/S**: Request/Response headers, Status Codes, and Web Traffic analysis.
    - **DHCP/ICMP**: Understanding how devices join networks and how `ping` is used for discovery.
- [ ] **Common Ports**: Knowing the "usual suspects" (21, 22, 25, 53, 80, 443, 445, 3389).

### 2. 🪟 Windows Internals
*The primary target in 90% of enterprise environments.*
- [ ] **Processes & Threads**: How `explorer.exe` differs from `svchost.exe` and how to spot "masquerading."
- [ ] **The Registry**: Understanding the "brain" of Windows—where persistence (Run keys) is hidden.
- [ ] **Windows Event Logs**: The gold mine. Security, System, and Application logs.
- [ ] **Authentication**: NTLM vs Kerberos (The foundation of Pass-the-Hash and Golden Ticket attacks).
- [ ] **File System**: NTFS permissions and the importance of the `C:\Windows\Temp` directory.

### 3. 🐧 Linux Internals
*The engine of the cloud and the target of high-value attacks.*
- [ ] **The Kernel & Shell**: Bash fundamentals and how the OS interacts with hardware.
- [ ] **Permissions & Ownership**: Root vs User, SUID bits, and privilege escalation.
- [ ] **Log Management**: `/var/log/syslog`, `/var/log/auth.log`, and `journalctl`.
- [ ] **Package Management**: Understanding `apt`, `yum`, and how malicious binaries are introduced.
- [ ] **Network Tooling**: `netstat`, `ss`, `tcpdump`, and `lsof`.

### 4. 🛡️ Core Security Concepts
*The theoretical framework for every decision you make in a SOC.*
- [ ] **CIA Triad**: Confidentiality, Integrity, Availability.
- [ ] **Defense in Depth**: Layering security (Firewall $\rightarrow$ EDR $\rightarrow$ IAM $\rightarrow$ Encryption).
- [ ] **Least Privilege**: The principle of giving only the access required to do the job.
- [ ] **AAA Framework**: Authentication, Authorization, and Accounting.

---

## 🚀 Quick Start Learning Path

| Topic | Recommended Resource | Type |
| :--- | :--- | :--- |
| **Networking** | [Professor Messer's Network+](https://www.professormesser.com/) | Video Course |
| **OS Internals** | [TryHackMe: Windows Fundamentals](https://tryhackme.com/) | Interactive Lab |
| **Linux Basics** | [OverTheWire: Bandit](https://overthewire.org/wargames/bandit/) | Wargame |
| **Security 101** | [CompTIA Security+ Guide](https://www.comptia.org/) | Certification/Study |

---

## 🛠️ Analyst's Toolset for Fundamentals
*Tools you should master to verify the concepts above:*
- **Wireshark**: For analyzing the "Networking" pillar.
- **Process Hacker / Sysinternals**: For analyzing the "Windows" pillar.
- **Linux Terminal**: For analyzing the "Linux" pillar.

---

<div align="center">

**Next Step:** $\rightarrow$ [02 - Threat Intelligence](./../02-threat-intelligence/)

</div>
