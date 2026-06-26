# 🛠️ The Ultimate SOC Lab Evolution Guide

This guide takes you from a complete beginner to a professional-level home lab. We follow a "Build-as-you-Learn" approach to avoid hardware burnout and cognitive overload.

---

## 💻 Hardware Requirements (Estimated)
| Stage | Minimum RAM | Recommended RAM | Storage |
| :--- | :--- | :--- | :--- |
| **Stage 1** | 8 GB | 16 GB | 100 GB SSD |
| **Stage 2** | 16 GB | 32 GB | 250 GB SSD |
| **Stage 3** | 32 GB | 64 GB+ | 500 GB+ SSD |

**Virtualization Platform**: VirtualBox (Free), VMware Workstation Player (Free), or Proxmox (Advanced/Server).

---

## 🟢 Stage 1: The Foundational Lab (The Basics)
*Goal: Understand how an action on a target creates a log on a server.*

### The Setup
1.  **Attacker VM**: Kali Linux (Lightweight version).
2.  **Target VM**: Windows 10 (Evaluation ISO).
3.  **SIEM VM**: Wazuh (All-in-one installation).

### The Workflow
- **Attack**: Use Kali to perform a simple brute-force or a reverse shell.
- **Detect**: Check the Wazuh dashboard to see the alert triggered.
- **Analyze**: Look at the raw logs to see exactly which process started the attack.

---

## 🟡 Stage 2: The Networked Lab (Intermediate)
*Goal: Move beyond endpoint logs to network-level visibility.*

### The Setup (Additions)
1.  **Network Gateway**: **pfSense** or **OPNsense**.
    *   *Config*: Create two networks (WAN and LAN). All other VMs must use pfSense as their Gateway/DNS.
2.  **Traffic Analysis**: Install **Wireshark** on the gateway or use a mirrored port.

### The Workflow
- **Attack**: Perform a network scan (Nmap) or a Man-in-the-Middle (MitM) attack.
- **Detect**: Use pfSense logs to see blocked connections.
- **Analyze**: Capture a `.pcap` file of the attack and analyze the packet headers in Wireshark.

---

## 🔴 Stage 3: The Professional Enterprise (Advanced)
*Goal: Simulate a real corporate environment with Active Directory and advanced telemetry.*

### The Setup (The Full Stack)
1.  **Identity Layer**: 
    *   **Windows Server 2022**: Promoted to Domain Controller (AD DS).
    *   Create a fake corporate domain (e.g., `corp.local`) with users and groups.
2.  **The SOC Stack**: **Security Onion**.
    *   This integrates **Zeek** (Network Metadata), **Suricata** (IDS/IPS), and **Elasticsearch/Kibana** (SIEM).
3.  **Advanced Endpoints**:
    *   Windows 10/11 joined to the Domain.
    *   **Sysmon (System Monitor)**: Installed via GPO to provide deep visibility into process creation and network connections.
    *   Ubuntu Server (Hosting a fake web app/database to attack).
4.  **The Attacker**: Kali Linux (Positioned in a separate "External" network).

### The Professional Workflow (The SOC Loop)
1.  **Execution**: Execute a complex attack chain (e.g., Phishing $\rightarrow$ User Execution $\rightarrow$ Local Admin $\rightarrow$ Domain Admin).
2.  **Telemetry**: 
    *   **Endpoint**: Sysmon catches the `powershell.exe` spawning a weird process.
    *   **Network**: Suricata catches the C2 (Command & Control) heartbeat.
    *   **Identity**: Windows Event Logs (ID 4624/4625) show the brute force on the Domain Controller.
3.  **Correlation**: Use the SIEM to correlate the network alert with the endpoint process.
4.  **Remediation**: Practice isolating the VM and cleaning the persistence mechanism.

---

## 🚀 Summary Table: Lab Components

| Component | Stage 1 | Stage 2 | Stage 3 | Purpose |
| :--- | :---: | :---: | :---: | :--- |
| **Kali Linux** | ✅ | ✅ | ✅ | Offensive Testing |
| **Windows 10** | ✅ | ✅ | ✅ | Endpoint Telemetry |
| **Wazuh** | ✅ | ✅ | ❌ | Basic XDR/SIEM |
| **pfSense** | ❌ | ✅ | ✅ | Network Control/Logging |
| **Windows Server**| ❌ | ❌ | ✅ | Active Directory / Identity |
| **Security Onion**| ❌ | ❌ | ✅ | Full-Scale SOC Suite |
| **Sysmon** | ❌ | ❌ | ✅ | Deep Endpoint Visibility |
