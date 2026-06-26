# The Ultimate SOC Lab Evolution Guide

This guide takes you from a complete beginner to a professional-level home lab using a **Build-as-you-Learn** approach — each stage is fully functional on its own before you add the next layer. No hardware burnout, no cognitive overload.

---

## Hardware Requirements

| Stage | Minimum RAM | Recommended RAM | Storage | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Stage 1 | 8 GB | 16 GB | 100 GB SSD | Single attacker + target + SIEM |
| Stage 2 | 16 GB | 32 GB | 250 GB SSD | Add network layer + Zeek |
| Stage 3 | 32 GB | 64 GB+ | 500 GB+ SSD | Full enterprise stack |

**Virtualization Platform**: VirtualBox (free, beginner-friendly), VMware Workstation Player (free, better performance), or Proxmox (advanced, bare-metal hypervisor for dedicated lab machines).

> **Tip**: If your hardware is limited, don't run every VM simultaneously. Snapshots are your best friend — take one after every major config change before you break something.

---

## Stage 1 — The Foundational Lab

*Goal: Understand how an action on a target creates a log on a server. Master this loop before adding complexity.*

### VMs

| VM | OS | Role |
| :--- | :--- | :--- |
| Attacker | Kali Linux (lightweight ISO) | Offensive testing |
| Target | Windows 10 Evaluation | Endpoint telemetry |
| SIEM | Wazuh (all-in-one OVA) | Detection + alerting |

### Key configuration — don't skip this

Install **Sysmon** on the Windows 10 VM before you do anything else. Without it, Windows event logs give you shallow telemetry at best — you'll miss process creation chains, child process spawning, network connections initiated by processes, and DLL image loads. These are exactly the things that matter in an investigation.

Use the **SwiftOnSecurity Sysmon config** as your baseline. It's the community standard and covers the most common attacker techniques without flooding you with noise:

```
https://github.com/SwiftOnSecurity/sysmon-config
```

Key Sysmon Event IDs to know from day one:

| Event ID | What it captures |
| :--- | :--- |
| 1 | Process creation (with full command line) |
| 3 | Network connection initiated by a process |
| 7 | Image/DLL loaded |
| 11 | File created |
| 13 | Registry value set |
| 22 | DNS query |

### The workflow

**Attack**: Use Kali to perform a brute-force against Windows RDP or generate a reverse shell with msfvenom.

**Detect**: Open the Wazuh dashboard and find the triggered alert. Note the rule ID, severity, and the raw log that fired it.

**Analyze**: Drill into the raw log. Find the process tree — what spawned what. Confirm which Sysmon Event ID caught it.

### Stage 1 exercises

**Exercise 1 — Brute Force Detection**
Run Hydra from Kali against Windows RDP. Confirm Event ID 4625 (failed logon) appears in Wazuh. Write a custom Wazuh rule that fires after 5 failed logins within 60 seconds from the same source IP. Expected outcome: a high-severity alert with the attacker's IP in the rule description.

**Exercise 2 — Reverse Shell Visibility**
Generate a reverse shell payload with msfvenom, execute it on Windows, and catch it with a Metasploit listener on Kali. Find the Sysmon Event ID 1 log showing `cmd.exe` or `powershell.exe` spawned as a child of an unexpected parent. Trace the full process tree in Wazuh.

**Exercise 3 — Custom Detection Rule**
Write a Wazuh rule that detects when `whoami.exe` or `net.exe` is executed within 30 seconds of a new network connection being established. This simulates post-exploitation enumeration.

---

## Stage 2 — The Networked Lab

*Goal: Move beyond endpoint logs to network-level visibility. Learn to correlate what the endpoint saw with what crossed the wire.*

### Additions to Stage 1

| VM | OS/Tool | Role |
| :--- | :--- | :--- |
| Network Gateway | pfSense or OPNsense | Firewall, DNS, network control |
| Traffic Analysis | Zeek (standalone) | Protocol-level network metadata |

### Network topology

```
[ Kali - Attacker ]
        |
  [ pfSense Gateway ]  ← Suricata IDS running inline here
        |
  +-----+-----+
  |           |
[ Windows 10 ] [ Zeek sensor ]
        |
     [ Wazuh ]
```

Create two network segments in your hypervisor:

- **WAN network**: Kali lives here, simulating an external attacker
- **LAN network**: Windows 10 and Wazuh live here, simulating the corporate network

All LAN VMs must use pfSense as their default gateway and DNS server. This forces all traffic through a chokepoint you control and can log.

### Why Zeek at Stage 2 (not just Wireshark)

Wireshark gives you raw packets. Zeek gives you structured metadata — conn.log, dns.log, http.log, ssl.log — without having to manually parse packet headers every time. This is what real SOC tools consume. Learn to read Zeek logs now before Security Onion abstracts them away in Stage 3.

Key Zeek logs to know:

| Log file | What it contains |
| :--- | :--- |
| conn.log | All network connections — src/dst IP, port, duration, bytes |
| dns.log | Every DNS query and response |
| http.log | HTTP method, URI, user-agent, response code |
| ssl.log | TLS handshake metadata, certificate details |
| files.log | Files transferred over the network with MD5/SHA1 hashes |

### Add Suricata to pfSense — don't wait for Stage 3

Install the Suricata package directly on pfSense and point it at the Emerging Threats Open ruleset. This gives you inline IDS/IPS at the network boundary in Stage 2, which is where it matters most. You'll get alerts on known-bad signatures before the traffic even reaches your endpoint.

### The workflow

**Attack**: Run an Nmap scan from Kali against the LAN. Then perform an ARP spoofing MitM attack using arpspoof or Bettercap.

**Detect**: Check pfSense firewall logs for blocked connections. Check Suricata alerts for scan signatures. Open Zeek conn.log and look for the scan pattern — hundreds of connections to sequential ports in a short window.

**Analyze**: Export a .pcap from the MitM session. Open it in Wireshark and confirm you can see cleartext HTTP traffic being intercepted. Cross-reference the Zeek ssl.log to identify any TLS downgrade attempts.

### Stage 2 exercises

**Exercise 1 — Network Scan Fingerprinting**
Run `nmap -sV -O` from Kali against the Windows 10 VM. In Zeek conn.log, identify the scan by looking for a single source IP hitting many destination ports in rapid succession. Write a Suricata rule that fires on this pattern.

**Exercise 2 — C2 Beaconing Simulation**
Use a Python script on Windows to send a GET request to a remote IP every 60 seconds, simulating C2 beaconing. In Zeek conn.log, identify the regular interval pattern. This is how threat hunters detect beaconing — consistent byte counts, consistent intervals.

**Exercise 3 — DNS Exfiltration Detection**
Use `iodine` or a simple script to encode data in DNS TXT queries and send it from Windows to Kali (acting as the DNS server). In Zeek dns.log, identify the anomalous query lengths and high volume of queries to a single domain. Write a detection for it.

---

## Stage 3 — The Professional Enterprise Lab

*Goal: Simulate a real corporate environment. Move from isolated detection to correlated, multi-source investigation across identity, endpoint, and network layers simultaneously.*

### Full stack

| VM | OS/Tool | Role |
| :--- | :--- | :--- |
| Domain Controller | Windows Server 2022 | Active Directory, DNS, GPO |
| Workstations | Windows 10/11 (domain-joined) | Endpoint telemetry via Sysmon + Wazuh agent |
| Linux Server | Ubuntu Server 22.04 | Fake web app / database target |
| SOC Platform | Security Onion | Zeek + Suricata + Elasticsearch + Kibana |
| XDR Platform | Wazuh (keep it from Stage 2) | Endpoint detection, file integrity, compliance |
| Email Server | GoPhish + Postfix | Phishing simulation and email attack chain |
| Deception Layer | OpenCanary | Honeypot-based lateral movement detection |
| Attacker | Kali Linux | Positioned in a separate External network segment |

### Network topology

```
[ Internet / External Network ]
           |
      [ Kali Linux ]  ← attacker positioned outside
           |
     [ pfSense ]  ← Suricata inline IDS, firewall boundary
           |
    +------+--------+
    |                |
[ DMZ Network ]   [ Corporate LAN ]
[ GoPhish ]       [ DC: corp.local ]
[ Ubuntu Server ] [ Win10 Workstation x2 ]
                  [ Wazuh Manager ]
                  [ Security Onion ]
                  [ OpenCanary Honeypot ]
```

### Identity layer — Active Directory setup

Promote Windows Server 2022 to a Domain Controller with the domain `corp.local`. Create a realistic user structure:

```
corp.local
├── OU: IT
│   ├── User: j.smith (helpdesk, local admin on workstations)
│   └── User: svc_backup (service account, no interactive logon)
├── OU: Finance
│   ├── User: a.jones (standard user)
│   └── User: b.kumar (standard user)
└── OU: Servers
    └── Computer: FILESERVER01
```

Create at least one service account with a weak password — you'll use it for Kerberoasting practice. Create a GPO that deploys Sysmon with the SwiftOnSecurity config to all domain-joined workstations automatically. This is how real enterprises deploy endpoint telemetry.

Critical AD Event IDs to monitor:

| Event ID | Meaning |
| :--- | :--- |
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon using explicit credentials (pass-the-hash indicator) |
| 4672 | Special privileges assigned (admin logon) |
| 4688 | Process creation (enable with audit policy) |
| 4720 | User account created |
| 4728 | Member added to security-enabled global group |
| 4768 | Kerberos TGT requested |
| 4769 | Kerberos service ticket requested (Kerberoasting indicator) |
| 4771 | Kerberos pre-authentication failed |

### Log forwarding pipeline — the missing layer

In a real SOC, endpoints don't talk directly to the SIEM. There's a shipper in between. This is a critical concept that appears constantly in interviews and on the job.

For Wazuh: deploy **Wazuh agents** on all Windows and Linux endpoints. Agents forward to the Wazuh Manager which normalises and enriches before indexing.

For Security Onion: deploy **Elastic Agent** on endpoints for host-based telemetry feeding into the Security Onion Elasticsearch backend.

The pipeline looks like this:

```
Sysmon → Windows Event Log → Wazuh Agent → Wazuh Manager → Elasticsearch
                                                                    ↑
                          Zeek / Suricata → Security Onion ────────┘
```

Correlating endpoint and network alerts using a shared timestamp and IP is where real investigations happen.

### Deception layer — OpenCanary

Deploy OpenCanary on a lightweight Ubuntu VM and configure it to impersonate a Windows file share, an RDP endpoint, and an HTTP server. Give it a believable hostname like `FILESERVER02` and join it to the domain (or just make it visible on the LAN).

Any connection to OpenCanary is an alert. There is no legitimate reason for a user to connect to it. When your simulated attacker does lateral movement and touches the honeypot, you get an immediate high-fidelity alert with zero false positives.

This teaches a fundamental blue team concept: **detection through deception**, not just signature matching.

### Purple teaming with Atomic Red Team

Install Atomic Red Team on a domain-joined Windows workstation:

```powershell
Install-Module -Name invoke-atomicredteam -Force
Import-Module invoke-atomicredteam
```

Before you declare any detection working, test it. Run the Atomic test for the technique you're trying to detect and confirm your SIEM fires. If it doesn't, your detection has a gap.

Example workflow for detecting credential dumping:

```powershell
# Simulate LSASS credential dumping (T1003.001)
Invoke-AtomicTest T1003.001

# Then check Security Onion / Wazuh for:
# - Sysmon Event ID 10 (process accessed lsass.exe)
# - Alert on OpenProcess call targeting lsass
```

This is purple teaming: red techniques, blue validation. It's how mature security teams maintain detection coverage.

### Phishing simulation with GoPhish

Deploy GoPhish in the DMZ and Postfix as your internal mail relay. Create a phishing campaign that sends a credential-harvesting email to your simulated user `a.jones@corp.local`. When `a.jones` clicks the link and enters credentials, trace the full kill chain:

```
Phishing email delivered
        ↓
User clicks link → GoPhish logs credential capture
        ↓
User executes attachment → Sysmon Event ID 1 (process creation)
        ↓
Reverse shell established → Sysmon Event ID 3 (network connection)
        ↓
Attacker runs whoami / net user → Sysmon Event ID 1
        ↓
Lateral movement to DC → Event ID 4648 on Domain Controller
        ↓
OpenCanary touched → honeypot alert fires
```

Correlate all of this in Security Onion using a timeline view. That end-to-end trace is what a Tier 2 SOC analyst does on a real incident.

### Stage 3 exercises

**Exercise 1 — Full Attack Chain (Phishing to Domain Admin)**
Execute: phishing email → user execution → local admin escalation → Mimikatz → pass-the-hash → lateral movement to DC → DCSync. Document every step with the corresponding SIEM alert and Event ID. Write a one-page IR report at the end as if you were handing it to a manager.

**Exercise 2 — Kerberoasting Detection**
From Kali (or an already-compromised workstation), run Impacket's GetUserSPNs.py to request a service ticket for the `svc_backup` account. In the SIEM, detect the anomaly via Event ID 4769 — a service ticket requested for an account that never has interactive logons, from a workstation that's never requested it before.

**Exercise 3 — Living off the Land (LOLBins)**
Perform post-exploitation using only built-in Windows binaries: `certutil.exe` for file download, `regsvr32.exe` for execution, `wmic.exe` for lateral movement. Verify that your Sysmon + Wazuh stack catches the anomalous usage of legitimate tools. Tune any rules that produce false positives.

**Exercise 4 — Incident Response Simulation**
Receive an "alert" (trigger it yourself without looking) and work the IR process cold: triage → scope → containment → eradication → recovery → lessons learned. Time yourself. Write a post-incident report. This is the closest you can get to a real SOC exercise without working in one.

---

## Summary Table — Lab Components

| Component | Stage 1 | Stage 2 | Stage 3 | Purpose |
| :--- | :---: | :---: | :---: | :--- |
| Kali Linux | ✅ | ✅ | ✅ | Offensive testing |
| Windows 10 | ✅ | ✅ | ✅ | Endpoint telemetry |
| Sysmon | ✅ | ✅ | ✅ | Deep endpoint visibility |
| Wazuh | ✅ | ✅ | ✅ | XDR, endpoint detection, compliance |
| pfSense + Suricata | ❌ | ✅ | ✅ | Network control, inline IDS |
| Zeek (standalone) | ❌ | ✅ | ✅ | Protocol-level network metadata |
| Windows Server 2022 | ❌ | ❌ | ✅ | Active Directory, identity layer |
| Security Onion | ❌ | ❌ | ✅ | Full SOC suite (Zeek + Suricata + ELK) |
| Elastic Agent | ❌ | ❌ | ✅ | Log forwarding pipeline |
| GoPhish + Postfix | ❌ | ❌ | ✅ | Phishing simulation |
| OpenCanary | ❌ | ❌ | ✅ | Honeypot / deception layer |
| Atomic Red Team | ❌ | ❌ | ✅ | Purple teaming, detection validation |

---

## What makes this lab professional-grade

Most home labs stop at "I set up a SIEM and it showed me an alert." What makes this different:

**Visibility across all three planes** — endpoint (Sysmon + Wazuh), network (Zeek + Suricata), and identity (AD Event IDs). Real incidents leave traces in all three. If you can only see one, you're blind to the others.

**A realistic log pipeline** — agents, shippers, and a manager sit between endpoints and the SIEM, exactly like production environments. You understand *how* data gets to the SIEM, not just what to do with it when it arrives.

**Deception-based detection** — OpenCanary means lateral movement triggers an alert before your signature-based rules even need to fire. High confidence, zero false positives.

**Purple teaming discipline** — Atomic Red Team means you don't assume your detections work. You test them. Every detection rule has a corresponding test that validates it.

**Structured exercises with expected outcomes** — you're not just poking things and watching dashboards. You're running defined attack chains, writing detection rules, and producing IR reports. That's what you'll do in a real SOC.

---

> Built for the [SOC Blue Team Resources](https://github.com/Ashiii27/soc-blue-team-resources) repository.
