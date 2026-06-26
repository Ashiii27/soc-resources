# Network Analysis for SOC Analysts — Comprehensive Notes

## Table of Contents
- [PART 1: NETWORKING FOUNDATIONS](#part-1-networking-foundations)
  - [1.1 Why Network Analysis Matters for SOC](#11-why-network-analysis-matters-for-soc)
  - [1.2 Types of Network Data](#12-types-of-network-data)
  - [1.3 Key Terminology — The Basics](#13-key-terminology--the-basics)
- [PART 2: OSI & TCP/IP MODELS IN DEPTH](#part-2-osi--tcpip-models-in-depth)
  - [2.1 The OSI Model (7 Layers)](#21-the-osi-model-7-layers)
  - [2.2 The TCP/IP Model (4 Layers)](#22-the-tcpip-model-4-layers)
  - [2.3 Encapsulation Process](#23-encapsulation-process)
  - [2.4 SOC Relevance of Each Layer](#24-soc-relevance-of-each-layer)
- [PART 3: CORE PROTOCOLS DEEP DIVE](#part-3-core-protocols-deep-dive)
  - [3.1 TCP (Transmission Control Protocol)](#31-tcp-transmission-control-protocol)
  - [3.2 UDP (User Datagram Protocol)](#32-udp-user-datagram-protocol)
  - [3.3 IP (Internet Protocol)](#33-ip-internet-protocol)
  - [3.4 ICMP (Internet Control Message Protocol)](#34-icmp-internet-control-message-protocol)
  - [3.5 ARP (Address Resolution Protocol)](#35-arp-address-resolution-protocol)
  - [3.6 DHCP (Dynamic Host Configuration Protocol)](#36-dhcp-dynamic-host-configuration-protocol)
- [PART 4: IP ADDRESSING, SUBNETTING & ROUTING](#part-4-ip-addressing-subnetting--routing)
  - [4.1 IPv4 Address Classes](#41-ipv4-address-classes-classful--legacy-but-still-referenced)
  - [4.2 Private (RFC 1918) Address Ranges](#42-private-rfc-1918-address-ranges)
  - [4.3 Special Addresses SOC Analysts Must Know](#43-special-addresses-soc-analysts-must-know)
  - [4.4 CIDR Notation & Subnet Quick Reference](#44-cidr-notation--subnet-quick-reference)
  - [4.5 NAT (Network Address Translation)](#45-nat-network-address-translation)
  - [4.6 Routing Basics](#46-routing-basics)
- [PART 5: NETWORK DEVICES & ARCHITECTURE](#part-5-network-devices--architecture)
  - [5.1 Core Devices](#51-core-devices)
  - [5.2 Network Segmentation](#52-network-segmentation)
  - [5.3 Network Architecture Patterns](#53-network-architecture-patterns)
  - [5.4 Where to Place Sensors (TAP/SPAN)](#54-where-to-place-sensors-tapspan)
- [PART 6: PACKET ANATOMY & ENCAPSULATION](#part-6-packet-anatomy--encapsulation)
  - [6.1 Ethernet Frame (Layer 2)](#61-ethernet-frame-layer-2)
  - [6.2 Complete Packet Example](#62-complete-packet-example)
- [PART 7: TRAFFIC CAPTURE & TOOLS](#part-7-traffic-capture--tools)
  - [7.1 Capture Methods](#71-capture-methods)
  - [7.2 Essential Tools](#72-essential-tools)
- [PART 8: WIRESHARK MASTERY](#part-8-wireshark-mastery)
  - [8.1 Display Filters vs Capture Filters](#81-display-filters-vs-capture-filters)
  - [8.2 Essential Display Filters](#82-essential-display-filters)
  - [8.3 Wireshark Features for SOC](#83-wireshark-features-for-soc)
  - [8.4 Wireshark Columns Configuration for SOC](#84-wireshark-columns-configuration-for-soc)
- [PART 9: NETWORK BASELINES & TRAFFIC PROFILING](#part-9-network-baselines--traffic-profiling)
  - [9.1 What Is Baselining?](#91-what-is-baselining)
  - [9.2 What to Baseline](#92-what-to-baseline)
  - [9.3 Anomaly Indicators](#93-anomaly-indicators)
- [PART 10: DNS ANALYSIS](#part-10-dns-analysis)
  - [10.1 DNS Fundamentals](#101-dns-fundamentals)
  - [10.2 DNS Attacks & Abuse](#102-dns-attacks--abuse)
  - [10.3 DNS Analysis with Zeek Logs](#103-dns-analysis-with-zeek-logs)
- [PART 11: HTTP/HTTPS ANALYSIS](#part-11-httphttps-analysis)
  - [11.1 HTTP Fundamentals](#111-http-fundamentals)
  - [11.2 HTTP Headers of Interest to SOC](#112-http-headers-of-interest-to-soc)
  - [11.3 Suspicious HTTP Patterns](#113-suspicious-http-patterns)
  - [11.4 HTTPS / TLS Analysis](#114-https--tls-analysis)
  - [11.5 SSL/TLS Decryption Methods](#115-ssltls-decryption-methods)
- [PART 12: EMAIL PROTOCOL ANALYSIS](#part-12-email-protocol-analysis)
  - [12.1 Email Protocols](#121-email-protocols)
  - [12.2 SMTP Analysis](#122-smtp-analysis)
  - [12.3 Email Header Analysis](#123-email-header-analysis)
- [PART 13: ENCRYPTED TRAFFIC ANALYSIS (ETA)](#part-13-encrypted-traffic-analysis-eta)
  - [13.1 The Challenge](#131-the-challenge)
  - [13.2 What You CAN See in Encrypted Traffic](#132-what-you-can-see-in-encrypted-traffic)
  - [13.3 Encrypted Traffic Analysis Techniques](#133-encrypted-traffic-analysis-techniques)
- [PART 14: LATERAL MOVEMENT DETECTION](#part-14-lateral-movement-detection)
  - [14.1 What Is Lateral Movement?](#141-what-is-lateral-movement)
  - [14.2 Common Lateral Movement Techniques & Network Signatures](#142-common-lateral-movement-techniques--network-signatures)
  - [14.3 Lateral Movement Detection Strategy](#143-lateral-movement-detection-strategy)
- [PART 15: C2 (COMMAND & CONTROL) TRAFFIC ANALYSIS](#part-15-c2-command--control-traffic-analysis)
  - [15.1 C2 Communication Concepts](#151-c2-communication-concepts)
  - [15.2 Beaconing Detection](#152-beaconing-detection)
  - [15.3 Common C2 Frameworks & Their Network Signatures](#153-common-c2-frameworks--their-network-signatures)
  - [15.4 C2 Over DNS (Detailed)](#154-c2-over-dns-detailed)
  - [15.5 C2 Over HTTPS](#155-c2-over-https)
- [PART 16: DATA EXFILTRATION DETECTION](#part-16-data-exfiltration-detection)
  - [16.1 Exfiltration Channels](#161-exfiltration-channels)
  - [16.2 Network Indicators of Exfiltration](#162-network-indicators-of-exfiltration)
  - [16.3 Exfiltration Detection Strategies](#163-exfiltration-detection-strategies)
- [PART 17: NETWORK-BASED ATTACK PATTERNS](#part-17-network-based-attack-patterns)
  - [17.1 Reconnaissance](#171-reconnaissance)
  - [17.2 Man-in-the-Middle (MitM) Attacks](#172-man-in-the-middle-mitm-attacks)
  - [17.3 Denial of Service (DoS/DDoS)](#173-denial-of-service-dosddos)
  - [17.4 Brute Force Attacks (Network Perspective)](#174-brute-force-attacks-network-perspective)
  - [17.5 Exploitation](#175-exploitation)
- [PART 18: IDS/IPS & SIGNATURE ANALYSIS](#part-18-idsips--signature-analysis)
  - [18.1 IDS vs IPS](#181-ids-vs-ips)
  - [18.2 Snort/Suricata Rule Anatomy](#182-snortsuricata-rule-anatomy)
  - [18.3 Rule Components Explained](#rule-components-explained)
  - [18.4 Understanding IDS Alerts in SOC](#184-understanding-ids-alerts-in-soc)
  - [18.5 Common Rule Sources](#185-common-rule-sources)
- [PART 19: NETFLOW / sFlow / IPFIX ANALYSIS](#part-19-netflow--sflow--ipfix-analysis)
  - [19.1 What Is NetFlow?](#191-what-is-netflow)
  - [19.2 NetFlow vs PCAP](#192-netflow-vs-pcap)
  - [19.3 NetFlow Analysis Use Cases](#193-netflow-analysis-use-cases)
  - [19.4 NetFlow Analysis Tools](#194-netflow-analysis-tools)
- [PART 20: LOG CORRELATION WITH NETWORK DATA](#part-20-log-correlation-with-network-data)
  - [20.1 Correlation Sources](#201-correlation-sources)
  - [20.2 Common Correlation Scenarios](#202-common-correlation-scenarios)
  - [20.3 SIEM Queries & Correlation Rules](#203-siem-queries--correlation-rules)
- [PART 21: WIRELESS NETWORK ANALYSIS](#part-21-wireless-network-analysis)
  - [21.1 Wireless Standards](#211-wireless-standards)
  - [21.2 Wireless Security Protocols](#212-wireless-security-protocols)
  - [21.3 Wireless Attacks](#213-wireless-attacks)
  - [21.4 Wireless Capture](#214-wireless-capture)
- [PART 22: CLOUD & VIRTUAL NETWORK ANALYSIS](#part-22-cloud--virtual-network-analysis)
  - [22.1 Cloud Networking Concepts](#221-cloud-networking-concepts)
  - [22.2 Cloud Network Monitoring](#222-cloud-network-monitoring)
  - [22.3 Cloud-Specific Threats](#223-cloud-specific-threats)
  - [22.4 Container & Kubernetes Network Analysis](#224-container--kubernetes-network-analysis)
- [PART 23: ZERO TRUST & MICRO-SEGMENTATION](#part-23-zero-trust--micro-segmentation)
  - [23.1 Zero Trust Principles](#231-zero-trust-principles)
  - [23.2 Micro-Segmentation](#232-micro-segmentation)
- [PART 24: THREAT INTELLIGENCE & NETWORK IoCs](#part-24-threat-intelligence--network-iocs)
  - [24.1 Network-Based Indicators of Compromise](#241-network-based-indicators-of-compromise)
  - [24.2 Threat Intelligence Feeds](#242-threat-intelligence-feeds)
  - [24.3 Using Threat Intelligence in Network Analysis](#243-using-threat-intelligence-in-network-analysis)
  - [24.4 Pivoting from IoCs](#244-pivoting-from-iocs)
- [PART 25: ADVANCED FORENSIC TECHNIQUES](#part-25-advanced-forensic-techniques)
  - [25.1 Full Packet Capture Forensics](#251-full-packet-capture-forensics)
  - [25.2 Network Forensics Methodology](#252-network-forensics-methodology)
  - [25.3 Protocol Anomaly Detection](#253-protocol-anomaly-detection)
  - [25.4 Network Timeline Analysis](#254-network-timeline-analysis)
  - [25.5 Traffic Decryption Techniques](#255-traffic-decryption-techniques)
- [PART 26: PROFESSIONAL TERMINOLOGY & FRAMEWORKS](#part-26-professional-terminology--frameworks)
  - [26.1 SOC-Specific Network Terms](#261-soc-specific-network-terms)
  - [26.2 MITRE ATT&CK Network-Relevant Techniques](#262-mitre-attck-network-relevant-techniques)
  - [26.3 Key Port Numbers SOC Analysts Must Know](#263-key-port-numbers-soc-analysts-must-know)
- [PART 27: PRACTICAL PLAYBOOKS & SOPs](#part-27-practical-playbooks--sops)
  - [27.1 Playbook: Investigating a Suspicious Outbound Connection](#271-playbook-investigating-a-suspicious-outbound-connection)
  - [27.2 Playbook: Investigating Potential Data Exfiltration](#272-playbook-investigating-potential-data-exfiltration)
  - [27.3 Playbook: Investigating DNS Tunneling](#273-playbook-investigating-dns-tunneling)
  - [27.4 Quick Reference: Wireshark Analysis Checklist](#274-quick-reference-wireshark-analysis-checklist)
- [APPENDIX A: COMMON WIRESHARK DISPLAY FILTER CHEAT SHEET](#appendix-a-common-wireshark-display-filter-cheat-sheet)
- [APPENDIX B: ZEEK LOG FILES REFERENCE](#appendix-b-zeek-log-files-reference)

---

# PART 1: NETWORKING FOUNDATIONS

## 1.1 Why Network Analysis Matters for SOC

Every cyberattack traverses the network at some point. Network data is:
- **Tamper-resistant**: Harder for attackers to tamper with than host logs.
- **Source of truth**: A "source of truth" — packets don't lie.
- **Always available**: Available even when endpoint tools fail or are disabled.
- **Visibility**: Critical for detecting lateral movement, exfiltration, C2.

## 1.2 Types of Network Data

| Data Type | What It Is | Depth | Example Tool |
| :--- | :--- | :--- | :--- |
| **Full Packet Capture (PCAP)** | Complete copy of every bit on the wire | Deepest | Wireshark, tcpdump, Moloch/Arkime |
| **NetFlow/Metadata** | Summary records (src/dst IP, port, bytes, duration) | Medium | SiLK, nfdump, Elastic |
| **Log Data** | Device-generated event records | Varies | Firewall logs, proxy logs |
| **Alert Data** | IDS/IPS triggered signatures | Shallow | Snort, Suricata, Zeek notices |
| **Endpoint Network Telemetry** | Host-level network activity | Host-focused | Sysmon (Event ID 3), EDR |

## 1.3 Key Terminology — The Basics

- **Packet**: The fundamental unit of data transmitted over a network.
- **Frame**: Layer 2 (Data Link) PDU; includes MAC addresses.
- **Segment**: Layer 4 (Transport) PDU for TCP.
- **Datagram**: Layer 4 PDU for UDP; also Layer 3 PDU for IP.
- **PDU (Protocol Data Unit)**: Generic term for data at any layer.
- **Payload**: The actual data being carried (excluding headers).
- **Header**: Metadata prepended to payload (addressing, control info).
- **Trailer**: Metadata appended (e.g., FCS in Ethernet frames).
- **Bandwidth**: Maximum data transfer rate of a network link.
- **Throughput**: Actual data transfer rate achieved.
- **Latency**: Time delay for data to travel from source to destination.
- **Jitter**: Variation in latency over time.
- **MTU (Maximum Transmission Unit)**: Largest packet size a link can carry.
- **TTL (Time To Live)**: Hop counter; decremented at each router.

---

# PART 2: OSI & TCP/IP MODELS IN DEPTH

## 2.1 The OSI Model (7 Layers)

- **Layer 7 — Application** → User-facing protocols (HTTP, DNS, FTP, SMTP)
- **Layer 6 — Presentation** → Data formatting, encryption, compression (SSL/TLS, JPEG, ASCII)
- **Layer 5 — Session** → Session management (NetBIOS, RPC, SOCKS)
- **Layer 4 — Transport** → End-to-end delivery (TCP, UDP, SCTP)
- **Layer 3 — Network** → Logical addressing & routing (IP, ICMP, IGMP, IPsec)
- **Layer 2 — Data Link** → Physical addressing & framing (Ethernet, ARP, Wi-Fi/802.11)
- **Layer 1 — Physical** → Bits on the wire (cables, voltages, frequencies)

> [!TIP]
> **Mnemonic (top-down)**: **A**ll **P**eople **S**eem **T**o **N**eed **D**ata **P**rocessing  
> **Mnemonic (bottom-up)**: **P**lease **D**o **N**ot **T**hrow **S**ausage **P**izza **A**way

## 2.2 The TCP/IP Model (4 Layers)

- **Application** → OSI Layers 5-7 (HTTP, DNS, SSH, etc.)
- **Transport** → OSI Layer 4 (TCP, UDP)
- **Internet** → OSI Layer 3 (IP, ICMP, ARP*)
- **Network Access** → OSI Layers 1-2 (Ethernet, Wi-Fi)

## 2.3 Encapsulation Process

```text
[Application Data]
        ↓ Application layer adds protocol headers (e.g., HTTP header)
[L7/L5 Header | Data]
        ↓ Transport layer adds TCP/UDP header → SEGMENT/DATAGRAM
[TCP Header | L7 Header | Data]
        ↓ Network layer adds IP header → PACKET
[IP Header | TCP Header | L7 Header | Data]
        ↓ Data Link layer adds Ethernet header + trailer → FRAME
[Eth Header | IP Header | TCP Header | L7 Header | Data | FCS]
        ↓ Physical layer converts to bits on the wire
[101010101010101010101010101010...]
```
De-encapsulation is the reverse process at the receiving end.

## 2.4 SOC Relevance of Each Layer

- **Layer 1-2**: MAC spoofing, ARP poisoning, VLAN hopping, rogue devices
- **Layer 3**: IP spoofing, ICMP tunneling, routing attacks, fragmentation attacks
- **Layer 4**: Port scanning, SYN floods, session hijacking, abnormal flags
- **Layer 5**: Session fixation, RPC exploitation
- **Layer 6**: SSL/TLS attacks (downgrade, stripping), certificate anomalies
- **Layer 7**: SQLi, XSS, malware downloads, C2 beaconing, DNS tunneling

---

# PART 3: CORE PROTOCOLS DEEP DIVE

## 3.1 TCP (Transmission Control Protocol)

### TCP Header Structure (20-60 bytes)

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |Reserv|C|E|U|A|P|R|S|F|                               |
| Offset| ed   |W|C|R|C|S|S|Y|I|            Window Size         |
|       |      |R|E|G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### TCP Flags — Critical for SOC Analysis

- **SYN (S)** — Initiate connection
- **ACK (A)** — Acknowledge received data
- **FIN (F)** — Graceful connection termination
- **RST (R)** — Abrupt connection reset
- **PSH (P)** — Push data to application immediately
- **URG (U)** — Urgent data pointer is valid
- **ECE** — ECN Echo (congestion notification)
- **CWR** — Congestion Window Reduced

### TCP Three-Way Handshake

```text
Client → Server:  SYN         (seq=x)
Server → Client:  SYN-ACK     (seq=y, ack=x+1)
Client → Server:  ACK         (seq=x+1, ack=y+1)

Connection ESTABLISHED
```

### TCP Four-Way Teardown

```text
Host A → Host B:  FIN-ACK
Host B → Host A:  ACK
Host B → Host A:  FIN-ACK
Host A → Host B:  ACK

Connection CLOSED
```

### TCP States (Important for analysis)

- **LISTEN** — Waiting for incoming connections
- **SYN_SENT** — SYN sent, waiting for SYN-ACK
- **SYN_RECEIVED** — SYN-ACK sent, waiting for ACK
- **ESTABLISHED** — Connection active
- **FIN_WAIT_1** — FIN sent, waiting for ACK
- **FIN_WAIT_2** — ACK to FIN received, waiting for peer's FIN
- **TIME_WAIT** — Waiting to ensure remote TCP received ACK (2×MSL)
- **CLOSE_WAIT** — Received FIN, waiting for application to close
- **LAST_ACK** — FIN sent after CLOSE_WAIT, waiting for ACK
- **CLOSED** — Connection terminated

### Suspicious TCP Patterns for SOC

- ✦ **SYN without completion** (SYN flood / half-open scan)
- ✦ **SYN to many ports from one source** (port scan — Nmap SYN scan)
- ✦ **SYN to one port on many hosts** (host sweep)
- ✦ **RST flood** (connection disruption)
- ✦ **FIN/NULL/XMAS scans** (flags: FIN only / none / FIN+PSH+URG)
- ✦ **Window size = 0 but data flowing** (possible evasion)
- ✦ **Abnormal sequence numbers** (session hijacking attempt)
- ✦ **Unusual TCP options** (OS fingerprinting — Nmap, p0f)
- ✦ **Out-of-order or overlapping fragments** (evasion of IDS)
- ✦ **Small MSS values** (fragmentation evasion)

## 3.2 UDP (User Datagram Protocol)

### UDP Header (8 bytes — simple)

```text
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Key Features
- **Connectionless** — no handshake
- **No guaranteed delivery**, no ordering
- **Faster, lower overhead** than TCP
- **Used by**: DNS (53), DHCP (67/68), SNMP (161/162), NTP (123), TFTP (69), syslog (514), VoIP/RTP, QUIC (443)

### Suspicious UDP Patterns

- ✦ **UDP flood** (volumetric DDoS)
- ✦ **DNS amplification** (small query → large response to spoofed IP)
- ✦ **NTP amplification** (monlist command)
- ✦ **SNMP amplification** (GetBulkRequest)
- ✦ **Large volumes of UDP to unusual ports**
- ✦ **DNS tunneling** (large TXT queries, high-entropy subdomain names)
- ✦ **QUIC traffic to unusual destinations** (can bypass inspection)

## 3.3 IP (Internet Protocol)

### IPv4 Header

```text
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|     Fragment Offset     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |       Header Checksum         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options (if any)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Key IP Fields for SOC

- **TTL**: Identifies OS family (Linux=64, Windows=128, Cisco=255). Also detects traceroute and ICMP tunneling.
- **Protocol field**: 1=ICMP, 6=TCP, 17=UDP, 47=GRE, 50=ESP, 51=AH.
- **Fragment Offset + Flags**: Fragmentation attacks, overlapping fragments.
- **Source IP**: Spoofing detection.
- **ToS/DSCP**: Can indicate tunneling or unusual QoS markings.
- **IP Options**: Source routing (LSRR/SSRR) — major red flag.

### IPv6 Considerations

- **128-bit addresses**
- **No NAT needed** (in theory) — every host publicly routable
- **Extension headers** can be used for evasion
- **IPv6 tunneled over IPv4** (6to4, Teredo, ISATAP) — can bypass controls
- **Unintentional enablement**: Many organizations have IPv6 enabled unknowingly
- **Dual-stack monitoring**: SOC must monitor both IPv4 and IPv6
- **Neighbor Discovery Protocol replaces ARP** — different attack surface

## 3.4 ICMP (Internet Control Message Protocol)

### ICMP Types

- **0** — Echo Reply
- **3** — Destination Unreachable
- **4** — Source Quench (deprecated)
- **5** — Redirect
- **8** — Echo Request
- **11** — Time Exceeded (TTL expired — traceroute relies on this)
- **13** — Timestamp Request
- **14** — Timestamp Reply

### ICMP in Attacks

- ✦ **ICMP Tunneling**: Data embedded in ICMP payload (echo request/reply)
  - *Detection*: ICMP packets with unusually large payloads
  - *Detection*: High frequency of ICMP between specific hosts
  - *Detection*: ICMP payload is not standard (normally 0x00 or alphabet pattern)
  - *Tools used*: `ptunnel`, `icmpsh`, `Hans`
- ✦ **ICMP Flood**: Ping flood / Smurf attack
- ✦ **ICMP Redirect**: Reroute victim's traffic through attacker
- ✦ **Traceroute**: Network reconnaissance (uses TTL=1,2,3... to map hops)
- ✦ **OS Fingerprinting via ICMP**: Different OS respond differently to unusual ICMP types

## 3.5 ARP (Address Resolution Protocol)

- Maps IP addresses to MAC addresses on a local network (Layer 2)
- **ARP Request**: "Who has 192.168.1.1? Tell 192.168.1.100" (broadcast)
- **ARP Reply**: "192.168.1.1 is at AA:BB:CC:DD:EE:FF" (unicast)
- **Gratuitref ARP**: Unsolicited ARP reply (used in failover, but also attacks)

### ARP Attacks

- ✦ **ARP Spoofing/Poisoning**: Attacker sends false ARP replies
  - Associates attacker's MAC with victim's IP → Enables Man-in-the-Middle (MitM)
  - *Detection*: Multiple IPs claiming same MAC, or one IP with changing MAC
  - *Tools*: `arpwatch`, `XArp`, Dynamic ARP Inspection (DAI) on switches
- ✦ **ARP Flood**: Overflow switch CAM table → switch degrades to hub mode
  - All traffic broadcast to all ports → attacker can sniff everything

## 3.6 DHCP (Dynamic Host Configuration Protocol)

### DORA Process
- **D — Discover**: Client broadcast ("I need an IP")
- **O — Offer**: Server ("Here's 192.168.1.50")
- **R — Request**: Client ("I'll take 192.168.1.50")
- **A — ACK**: Server ("Confirmed, it's yours")

### DHCP Attacks

- ✦ **DHCP Starvation**: Attacker requests all available IPs → legitimate hosts denied
- ✦ **Rogue DHCP Server**: Attacker provides malicious gateway/DNS to victims
- ✦ **Detection**: Monitor for unusual DHCP servers, excessive DISCOVER messages
- ✦ **Defense**: DHCP Snooping on managed switches

---

# PART 4: IP ADDRESSING, SUBNETTING & ROUTING

## 4.1 IPv4 Address Classes (Classful — Legacy but still referenced)

- **Class A**: 1.0.0.0 – 126.255.255.255 `/8` (16M hosts)
- **Class B**: 128.0.0.0 – 191.255.255.255 `/16` (65K hosts)
- **Class C**: 192.0.0.0 – 223.255.255.255 `/24` (254 hosts)
- **Class D**: 224.0.0.0 – 239.255.255.255 (Multicast)
- **Class E**: 240.0.0.0 – 255.255.255.255 (Experimental)

## 4.2 Private (RFC 1918) Address Ranges

- **10.0.0.0/8**: 10.0.0.0 – 10.255.255.255
- **172.16.0.0/12**: 172.16.0.0 – 172.31.255.255
- **192.168.0.0/16**: 192.168.0.0 – 192.168.255.255

## 4.3 Special Addresses SOC Analysts Must Know

- **127.0.0.0/8**: Loopback (localhost)
- **169.254.0.0/16**: Link-local (APIPA — no DHCP response)
- **0.0.0.0**: Default route / "any" address
- **255.255.255.255**: Limited broadcast
- **100.64.0.0/10**: Carrier-grade NAT (RFC 6598)
- **224.0.0.0/4**: Multicast
- **192.0.2.0/24**: Documentation/testing (RFC 5737)
- **198.51.100.0/24**: Documentation/testing (RFC 5737)
- **203.0.113.0/24**: Documentation/testing (RFC 5737)

## 4.4 CIDR Notation & Subnet Quick Reference

- `/32` = 1 host (255.255.255.255)
- `/31` = 2 hosts (255.255.255.254 — point-to-point links)
- `/30` = 4 addresses (255.255.255.252 — 2 usable)
- `/29` = 8 addresses (255.255.255.248 — 6 usable)
- `/28` = 16 addresses (255.255.255.240 — 14 usable)
- `/27` = 32 addresses (255.255.255.224 — 30 usable)
- `/26` = 64 addresses (255.255.255.192 — 62 usable)
- `/25` = 128 addresses (255.255.255.128 — 126 usable)
- `/24` = 256 addresses (255.255.255.0 — 254 usable)
- `/16` = 65,536 addresses (255.255.0.0)
- `/8` = 16,777,216 addresses (255.0.0.0)

## 4.5 NAT (Network Address Translation)

- **Static NAT**: 1:1 mapping (public ↔ private)
- **Dynamic NAT**: Pool of public IPs mapped dynamically
- **PAT/NAPT**: Many-to-one using port numbers (most common, aka "overloading" or "masquerading")

### SOC Relevance:
- NAT obscures true source IPs in internal logs.
- Must correlate NAT translations to identify actual internal hosts.
- Firewall/NAT logs are critical: `timestamp + src_ip + src_port + translated_ip`.
- Hairpin NAT / NAT loopback can create confusing traffic patterns.

## 4.6 Routing Basics

- **Static Routes**: Manually configured
- **Dynamic Routing**: Protocols: OSPF, BGP, EIGRP, RIP
- **Default Gateway**: Where packets go if no specific route matches
- **BGP Hijacking**: Attacker advertises routes for IP prefixes they don't own, redirecting traffic. Nation-state level attack; detection via RPKI, BGP monitoring tools.

### SOC should know:
- Internal routing table anomalies
- Unexpected next-hops
- Route poisoning in OSPF/EIGRP

---

# PART 5: NETWORK DEVICES & ARCHITECTURE

## 5.1 Core Devices

- **Hub** (L1): Broadcasts all traffic to all ports (obsolete, but appears in labs)
- **Switch** (L2): Forwards frames based on MAC address table (CAM table)
- **Router** (L3): Forwards packets based on IP routing table
- **Firewall** (L3-L7): Permits/denies traffic based on rules/policies
- **IDS**: Monitors traffic, generates alerts (passive)
- **IPS**: Monitors traffic, blocks threats (inline/active)
- **Proxy** (L7): Intermediary for client requests (forward/reverse)
- **Load Balancer**: Distributes traffic across servers
- **WAF**: Web Application Firewall; inspects HTTP/HTTPS
- **TAP**: Test Access Point; copies traffic for monitoring (passive)
- **SPAN Port**: Switch port mirroring (alternative to TAP)

## 5.2 Network Segmentation

- **VLAN (Virtual LAN)**:
  - Logical separation at Layer 2.
  - Trunk ports carry multiple VLANs (802.1Q tagging).
  - VLAN hopping attacks: double-tagging, switch spoofing.
- **DMZ (Demilitarized Zone)**:
  - Network segment between external and internal networks.
  - Hosts public-facing services (web, email, DNS).
  - Dual-firewall or single-firewall with three interfaces.
- **Zones (Firewall)**:
  - Trust zones: Internal (trusted), External (untrusted), DMZ (semi-trusted).
  - **Zero Trust**: No implicit trust based on network location.

## 5.3 Network Architecture Patterns

- **North-South Traffic**: Client ↔ Server (crosses perimeter). Traditional firewall inspection point.
- **East-West Traffic**: Server ↔ Server (internal/lateral).
  - Increasingly important for detecting lateral movement.
  - Micro-segmentation, internal firewalls, NDR tools.
- **Three-Tier Architecture**:
  - Core Layer: High-speed backbone
  - Distribution: Policy enforcement, VLAN routing
  - Access Layer: End-user connectivity
- **Spine-Leaf (Data Center)**:
  - Spine switches: Backbone
  - Leaf switches: Connect to servers
  - Every leaf connects to every spine (low latency, predictable)

## 5.4 Where to Place Sensors (TAP/SPAN)

Critical visibility points:
- ✦ Internet edge (between firewall and router)
- ✦ DMZ segments
- ✦ Between network zones / trust boundaries
- ✦ Core switch (east-west visibility)
- ✦ In front of critical assets (DB servers, DC, etc.)
- ✦ VPN concentrator egress
- ✦ Cloud VPC flow logs / virtual TAPs

---

# PART 6: PACKET ANATOMY & ENCAPSULATION

## 6.1 Ethernet Frame (Layer 2)

```text
+----------+----------+------+-------------------+-----+
| Dst MAC  | Src MAC  | Type |     Payload       | FCS |
| (6 bytes)| (6 bytes)|(2 B) |  (46-1500 bytes)  |(4 B)|
+----------+----------+------+-------------------+-----+
```

EtherType values:
- `0x0800` — IPv4
- `0x0806` — ARP
- `0x86DD` — IPv6
- `0x8100` — 802.1Q VLAN tag
- `0x8847` — MPLS

## 6.2 Complete Packet Example

```text
[Ethernet Header]
  Dst MAC: ff:ff:ff:ff:ff:ff (broadcast)
  Src MAC: aa:bb:cc:dd:ee:ff
  Type: 0x0800 (IPv4)
[IPv4 Header]
  Src IP: 192.168.1.100
  Dst IP: 8.8.8.8
  TTL: 128 (Windows)
  Protocol: 6 (TCP)
[TCP Header]
  Src Port: 49152
  Dst Port: 443 (HTTPS)
  Flags: SYN
  Seq: 0
  Window: 64240
[Payload]
  (TLS Client Hello in this case)
```

---

# PART 7: TRAFFIC CAPTURE & TOOLS

## 7.1 Capture Methods

1. **SPAN/Mirror Port**:
   - Switch copies traffic from one/many ports to a monitoring port.
   - *Pros*: Easy setup.
   - *Cons*: Can drop packets under load, may not capture errors, affects switch CPU.
2. **Network TAP (Test Access Point)**:
   - Hardware device inserted inline.
   - Copies all traffic including errors and malformed frames.
   - *Pros*: No packet loss, invisible to network, no performance impact.
   - *Cons*: Physical installation required, cost.
3. **Inline Capture**:
   - Device sits in the traffic path (IPS, proxy).
   - Can modify/block traffic.
4. **Host-Based Capture**:
   - tcpdump/Wireshark on the endpoint itself.
   - Sees only that host's traffic (post-NAT, decrypted if on host).
5. **Cloud-Native**:
   - VPC Flow Logs (AWS, GCP, Azure)
   - Packet Mirroring (AWS Traffic Mirroring, GCP Packet Mirroring)
   - Virtual TAPs

## 7.2 Essential Tools

### tcpdump (Command Line)

```bash
# Basic capture
tcpdump -i eth0

# Capture with verbose output
tcpdump -i eth0 -vvv

# Write to file
tcpdump -i eth0 -w capture.pcap

# Read from file
tcpdump -r capture.pcap

# Filter by host
tcpdump -i eth0 host 192.168.1.100

# Filter by port
tcpdump -i eth0 port 443

# Filter by protocol
tcpdump -i eth0 tcp
tcpdump -i eth0 icmp

# Complex filter: traffic from .100 to port 80 or 443
tcpdump -i eth0 'src host 192.168.1.100 and (dst port 80 or dst port 443)'

# Show packet contents in hex and ASCII
tcpdump -i eth0 -X

# Show only packet headers (no payload)
tcpdump -i eth0 -S -nn

# Capture first 100 packets
tcpdump -i eth0 -c 100

# Filter TCP flags (SYN only)
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'

# Filter by packet size
tcpdump -i eth0 'greater 1000'

# Capture ring buffer (rotate files)
tcpdump -i eth0 -w capture.pcap -C 100 -W 10
# -C 100 = 100MB per file, -W 10 = keep 10 files max
```

### BPF (Berkeley Packet Filter) Syntax

- **Primitives**: `host`, `net`, `port`, `portrange`, `src`, `dst`, `tcp`, `udp`, `icmp`, `arp`
- **Operators**: `and` (`&&`), `or` (`||`), `not` (`!`)

#### Examples:
```text
src host 10.0.0.1 and dst port 22
net 192.168.1.0/24
not port 53
tcp portrange 1-1024
ether host aa:bb:cc:dd:ee:ff
ip proto 1          (ICMP)
tcp[13] & 0x02 != 0 (SYN flag set — byte offset 13 in TCP header)
tcp[13] == 0x12     (SYN-ACK exactly)
ip[2:2] > 576       (IP total length > 576)
```

### tshark (Command-line Wireshark)

```bash
# Capture live
tshark -i eth0

# Read pcap
tshark -r capture.pcap

# Display filter
tshark -r capture.pcap -Y "http.request.method == GET"

# Specific fields
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport

# Statistics: protocol hierarchy
tshark -r capture.pcap -q -z io,phs

# Statistics: conversations
tshark -r capture.pcap -q -z conv,tcp

# Statistics: HTTP requests
tshark -r capture.pcap -q -z http,tree

# Export objects (files transferred)
tshark -r capture.pcap --export-objects http,exported_files/

# Decode as
tshark -r capture.pcap -d tcp.port==8080,http
```

### Other Critical Tools

- **Zeek (Bro)**:
  - Network security monitor.
  - Generates structured logs (`conn.log`, `dns.log`, `http.log`, `ssl.log`, etc.).
  - Scriptable for custom detection.
  - Produces metadata, not full PCAP.
- **Suricata**:
  - IDS/IPS engine.
  - Signature-based + protocol analysis.
  - Produces alerts, flow records, protocol logs.
  - Compatible with Snort rules + has own rule format.
- **Arkime (formerly Moloch)**:
  - Full packet capture + indexing system.
  - Web interface for searching/analyzing PCAPs at scale.
  - Integrates with Elasticsearch.
- **NetworkMiner**:
  - Windows-based network forensics tool.
  - Extracts files, images, credentials from PCAP.
  - OS fingerprinting, host profiling.
- **ngrep**: grep for network traffic patterns on packet payloads.
- **Capinfos**: PCAP file statistics (duration, packet count, file size).
- **Editcap**: Edit/trim/split PCAP files.
- **Mergecap**: Merge multiple PCAP files.
- **p0f**: Passive OS fingerprinting from TCP/IP characteristics.
- **SiLK / rwtools**: NetFlow analysis suite.
- **Nmap**: Network reconnaissance scanning tool. Understanding Nmap signatures helps SOC analysts identify active scans.

---

# PART 8: WIRESHARK MASTERY

## 8.1 Display Filters vs Capture Filters

- **Capture Filters**: Applied BEFORE capture (BPF syntax, cannot be changed after).
  - Use when you know exactly what you want and need to reduce capture size.
  - *Example*: `port 53`
- **Display Filters**: Applied AFTER capture (Wireshark syntax, flexible).
  - Use for analysis of already-captured traffic.
  - *Example*: `dns.qry.name contains "evil"`

## 8.2 Essential Display Filters

```text
# By IP
ip.addr == 192.168.1.100
ip.src == 10.0.0.1
ip.dst == 10.0.0.1
!(ip.addr == 192.168.1.1)

# By protocol
tcp
udp
dns
http
tls
icmp
arp
smb
smb2
kerberos
ldap
dhcp

# By port
tcp.port == 443
tcp.dstport == 80
udp.port == 53
tcp.srcport >= 49152

# TCP Flags
tcp.flags.syn == 1 && tcp.flags.ack == 0     # SYN scan
tcp.flags.reset == 1                          # RST packets
tcp.flags == 0x000                            # NULL scan
tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1  # XMAS scan

# HTTP
http.request.method == "GET"
http.request.method == "POST"
http.request.uri contains "admin"
http.response.code == 200
http.response.code >= 400
http.host contains "suspicious"
http.user_agent contains "python"
http.content_type contains "executable"

# DNS
dns.qry.name contains "evil.com"
dns.qry.type == 1        # A record
dns.qry.type == 28       # AAAA record
dns.qry.type == 16       # TXT record
dns.qry.type == 15       # MX record
dns.qry.name matches "^[a-z0-9]{30,}\."    # Long subdomain (tunneling indicator)
dns.resp.len > 512                           # Large DNS response

# TLS/SSL
tls.handshake.type == 1                      # Client Hello
tls.handshake.type == 2                      # Server Hello
tls.handshake.extensions.server_name contains "evil"    # SNI
tls.handshake.ciphersuite                    # Cipher suites offered
tls.record.version                           # TLS version
ssl.alert_message                            # TLS alerts

# SMB
smb2.cmd == 5                                # SMB2 Create (file access)
smb2.filename contains "password"

# Kerberos
kerberos.CNameString contains "admin"
kerberos.error_code != 0

# Size-based
frame.len > 1500
tcp.len > 0
udp.length > 512

# Time-based
frame.time >= "2024-01-01 00:00:00" && frame.time <= "2024-01-02 00:00:00"

# Follow streams
tcp.stream eq 5

# Errors/Retransmissions
tcp.analysis.retransmission
tcp.analysis.duplicate_ack
tcp.analysis.zero_window
tcp.analysis.flags
```

## 8.3 Wireshark Features for SOC

1. **Follow TCP/UDP/TLS Stream**:
   - Right-click packet → Follow → TCP Stream. Shows the full conversation in readable format.
2. **Protocol Hierarchy (Statistics → Protocol Hierarchy)**:
   - Shows percentage breakdown of protocols — useful for baselining and spotting unusual protocols.
3. **Conversations (Statistics → Conversations)**:
   - Shows all communication pairs, bytes transferred, duration. Sort by bytes to find large transfers (exfiltration).
4. **Endpoints (Statistics → Endpoints)**:
   - Shows all unique hosts communicating. Map → GeoIP visualization.
5. **IO Graphs (Statistics → IO Graphs)**:
   - Visualize traffic patterns over time. Add filters to compare and detect beaconing patterns (regular intervals).
6. **Expert Info (Analyze → Expert Information)**:
   - Wireshark's automated analysis. Shows errors, warnings, notes, chats. Great starting point for investigation.
7. **Export Objects (File → Export Objects → HTTP/SMB/TFTP/IMF)**:
   - Extract transferred files from the capture. Submit to sandbox/VirusTotal for analysis.
8. **Coloring Rules (View → Coloring Rules)**:
   - Customize colors for specific traffic patterns. Create rules for known-bad indicators.
9. **Profiles**:
   - Save different configurations for different analysis types (Malware analysis profile, IR profile, etc.).
10. **Decryption**:
    - TLS with pre-master secret log (`SSLKEYLOGFILE`)
    - WPA2 with PSK
    - Kerberos with keytab

## 8.4 Wireshark Columns Configuration for SOC

Recommended custom columns:
- **No.** — Packet number
- **Time** — Relative time (seconds since capture start)
- **Source** — Source IP
- **Destination** — Destination IP
- **Protocol** — Protocol name
- **Src Port** — `tcp.srcport || udp.srcport`
- **Dst Port** — `tcp.dstport || udp.dstport`
- **Length** — Frame length
- **Info** — Default info column

Optional additions:
- **TTL** — `ip.ttl`
- **TCP Stream** — `tcp.stream`
- **HTTP Host** — `http.host`
- **TLS SNI** — `tls.handshake.extensions.server_name`
- **DNS Query** — `dns.qry.name`

---

# PART 9: NETWORK BASELINES & TRAFFIC PROFILING

## 9.1 What Is Baselining?

A network baseline is a documented "normal" state of the network:
- Normal protocols and their distribution
- Typical traffic volumes by time of day/week
- Common communication patterns (who talks to whom)
- Expected port usage
- Normal DNS query patterns
- Typical packet sizes
- Average session durations

> "You can't find abnormal if you don't know normal."

## 9.2 What to Baseline

- ✦ Protocol distribution (% TCP, UDP, ICMP, other)
- ✦ Top talkers (hosts generating most traffic)
- ✦ Top destinations (external IPs/domains most contacted)
- ✦ Port usage patterns (services running, ephemeral port ranges)
- ✦ DNS query volume and top queried domains
- ✦ Average packet size by protocol
- ✦ Connection durations
- ✦ Traffic by time of day (business hours vs. off-hours)
- ✦ East-West vs. North-South ratios
- ✦ Bandwidth utilization per segment
- ✦ Failed connection rates
- ✦ Geographic distribution of external connections

## 9.3 Anomaly Indicators

- ✦ New protocol appearing (e.g., IRC suddenly active)
- ✦ Traffic to unusual ports (high-numbered ports, known C2 ports)
- ✦ Traffic to unusual countries or IPs
- ✦ Significant change in volume (spike or unusual sustained increase)
- ✦ Off-hours activity from hosts that are normally quiet
- ✦ New communication pairs (server A never talked to server B before)
- ✦ Unusual DNS patterns (high volume, new resolvers, unusual record types)
- ✦ Long-duration connections (possible C2 keep-alive)
- ✦ Periodic/regular connections at exact intervals (beaconing)
- ✦ Large outbound transfers (exfiltration)
- ✦ Encrypted traffic on non-standard ports
- ✦ Unresolved DNS before connection (direct IP access — common in malware)

---

# PART 10: DNS ANALYSIS

## 10.1 DNS Fundamentals

- **Port**: 53 (UDP primarily, TCP for zone transfers and large responses)

### Record Types:
- **A** — IPv4 address
- **AAAA** — IPv6 address
- **CNAME** — Canonical name (alias)
- **MX** — Mail exchange server
- **NS** — Name server
- **PTR** — Reverse DNS (IP → name)
- **SOA** — Start of Authority
- **TXT** — Text records (SPF, DKIM, verification, also tunneling!)
- **SRV** — Service locator
- **HINFO** — Host information
- **ANY** — Request all records (used in amplification attacks)

### Query Process:
```text
Client → Recursive Resolver → Root NS → TLD NS → Authoritative NS → Answer
```
(Caching reduces repeated queries)

## 10.2 DNS Attacks & Abuse

### DNS Tunneling
Technique: Encode data in DNS queries/responses
- Subdomain encoding: `base64data.evil.com`
- TXT record responses carrying large payloads
- Tools: `iodine`, `dnscat2`, `dns2tcp`, Cobalt Strike DNS beacon

#### Detection Indicators:
- ✦ Unusually long subdomain labels (>30 chars)
- ✦ High entropy in subdomain names (random-looking strings)
- ✦ High volume of DNS queries to a single domain
- ✦ Unusual record types (TXT, NULL, CNAME with long names)
- ✦ Large DNS responses (>512 bytes over UDP)
- ✦ Direct queries to external DNS servers (bypassing internal resolvers)
- ✦ High query frequency from a single host
- ✦ Domain names with unusual TLD patterns

#### Wireshark filters:
```wireshark
dns.qry.name.len > 50
dns.resp.len > 512
dns.qry.type == 16  (TXT)
dns.qry.type == 10  (NULL)
```

### DNS Amplification Attack
1. Attacker sends DNS query with spoofed source IP (victim's IP)
2. Uses open resolvers
3. Requests records that produce large responses (ANY, TXT)
4. Responses flood the victim

- *Amplification factor*: up to 70x
  
#### Detection:
- ✦ Large volume of DNS responses to a host that didn't query
- ✦ ANY queries from unusual sources
- ✦ Response size >> request size

### DNS Hijacking / Poisoning

#### Cache Poisoning:
- Attacker injects false DNS records into resolver cache → Victims directed to malicious IP

#### DNS Hijacking:
- Compromise registrar account → change NS records
- Modify router DNS settings → redirect queries

#### Detection:
- ✦ DNS responses from unexpected sources
- ✦ Multiple different answers for the same query
- ✦ Short TTL values in responses (attacker wants to change quickly)
- ✦ DNSSEC validation failures

### Domain Generation Algorithms (DGA)
Malware generates pseudo-random domain names algorithmically (e.g., `a3f7bc9d2e.com`, `x8k2m4n7p.net`).
- *Purpose*: Even if one C2 domain is blocked, others will resolve.

#### Detection:
- ✦ High entropy domain names
- ✦ Many `NXDOMAIN` (non-existent domain) responses
- ✦ Rapid querying of many unique, never-before-seen domains
- ✦ Machine learning models trained on DGA patterns
  
#### Wireshark:
```wireshark
dns.flags.rcode == 3  (NXDOMAIN)
```

### Fast Flux DNS
- **Single Flux**: Domain resolves to rapidly changing IPs (botnet nodes serve as proxies).
- **Double Flux**: Both A records AND NS records change rapidly.

#### Detection:
- ✦ Very low TTLs (30-300 seconds)
- ✦ Large number of unique IPs for a single domain
- ✦ IPs distributed across many ASNs/countries

## 10.3 DNS Analysis with Zeek Logs

Zeek `conn.log` fields for DNS (port 53):
- `ts`, `uid`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto`

Zeek `dns.log` fields:
- `ts` — Timestamp
- `uid` — Unique connection ID
- `id.orig_h` — Source IP
- `id.resp_h` — Destination IP (DNS server)
- `query` — Domain queried
- `qtype_name` — Query type (A, AAAA, TXT, etc.)
- `rcode_name` — Response code (NOERROR, NXDOMAIN, etc.)
- `answers` — Response answers
- `TTLs` — TTL values
- `rejected` — Whether query was rejected

#### Key analysis queries:
- Group by query, count → find most queried domains
- Filter `qtype_name == "TXT"` → tunneling candidates
- Filter `rcode_name == "NXDOMAIN"`, group by query → DGA candidates
- Filter `id.resp_h != internal_dns_server` → direct external DNS queries
- Filter `query length > 50` → potential tunneling

---

# PART 11: HTTP/HTTPS ANALYSIS

## 11.1 HTTP Fundamentals

- **Port**: 80 (HTTP), 443 (HTTPS), 8080/8443 (common alternates)

### HTTP Request Structure:
```text
METHOD URI HTTP/VERSION\r\n
Header: value\r\n
Header: value\r\n
\r\n
[Body]
```

### Common Methods:
- **GET** — Retrieve resource
- **POST** — Submit data
- **PUT** — Upload/replace resource
- **DELETE** — Remove resource
- **HEAD** — GET without body (reconnaissance)
- **OPTIONS** — Query supported methods
- **PATCH** — Partial modification
- **CONNECT** — Establish tunnel (used for HTTPS through proxy)

### HTTP Response Status Codes:
- **1xx** — Informational
- **2xx** — Success (200 OK, 201 Created, 204 No Content)
- **3xx** — Redirection (301 Moved, 302 Found, 304 Not Modified)
- **4xx** — Client Error (400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found)
- **5xx** — Server Error (500 Internal Server Error, 502 Bad Gateway, 503 Service Unavailable)

## 11.2 HTTP Headers of Interest to SOC

### Request Headers:
- `Host`: Target domain (critical for virtual hosting)
- `User-Agent`: Client software identifier
- `Referer`: Previous page
- `Cookie`: Session tokens
- `Authorization`: Credentials (Basic, Bearer)
- `Content-Type`: Format of body data
- `X-Forwarded-For`: Original client IP (through proxies)

### Response Headers:
- `Server`: Web server software
- `Set-Cookie`: Session management
- `Content-Type`: Response format
- `Content-Disposition`: File download instructions
- `X-Frame-Options`: Clickjacking protection
- `Content-Security-Policy`: XSS/injection protection
- `Location`: Redirect target (3xx responses)

## 11.3 Suspicious HTTP Patterns

- ✦ **Unusual User-Agents**:
  - `Python-urllib`, `curl`, `wget` (automated tools)
  - Empty User-Agent
  - Known malware User-Agents
  - User-Agent mismatches (e.g., Linux UA from Windows host)
- ✦ **HTTP to unusual ports** (8080, 8443, 4443, etc.)
- ✦ **POST requests with large body** to unknown domains (data exfiltration)
- ✦ **GET requests with long URLs** (data in URL parameters)
- ✦ **Beaconing**: Regular HTTP requests at fixed intervals (same URL, similar request size, periodic timing)
- ✦ **Directory traversal**: `../../etc/passwd` in URI
- ✦ **SQL injection**: `' OR 1=1--`, `UNION SELECT`, etc.
- ✦ **Webshell indicators**:
  - POST to unusual URI (e.g., `/images/upload.php`)
  - Small request, moderate response
  - `cmd=`, `exec=`, `shell=` parameters
  - Base64 encoded parameters
- ✦ **File downloads**:
  - `.exe`, `.dll`, `.scr`, `.bat`, `.ps1`, `.vbs`, `.hta` downloads
  - Content-Type mismatch (image/jpeg but file is `.exe`)
  - `Content-Disposition` with suspicious filenames
- ✦ **HTTP CONNECT method** to unusual ports (tunneling through proxy)
- ✦ **Excessive 4xx/5xx errors** from one source (scanning/bruteforcing)

## 11.4 HTTPS / TLS Analysis

Since HTTPS is encrypted, SOC focuses on:

### TLS Client Hello (visible in cleartext):
- ✦ **Server Name Indication (SNI)**: Domain being accessed.
- ✦ **Cipher suites offered**: Weak ciphers may indicate old/malicious client.
- ✦ **TLS version**: TLS 1.0/1.1 = deprecated/suspicious.
- ✦ **Extensions**: ALPN, session ticket, etc.
- ✦ **JA3 fingerprint**: Hash of Client Hello parameters.

### TLS Server Hello (visible in cleartext):
- ✦ Chosen cipher suite.
- ✦ **Certificate**: Subject, Issuer, validity, SAN.
- ✦ **JA3S fingerprint**: Hash of Server Hello parameters.
- ✦ Self-signed certificates = suspicious.
- ✦ Let's Encrypt certs on suspicious domains.
- ✦ Certificate age (very new = potentially malicious).
- ✦ Mismatched CN/SAN vs. actual domain.

### TLS Certificate Red Flags:
- ✦ Self-signed certificates
- ✦ Expired certificates
- ✦ Certificates with IP addresses instead of domains
- ✦ Wildcard certs on suspicious domains
- ✦ Very short validity periods
- ✦ Unknown/untrusted Certificate Authorities
- ✦ Subject doesn't match SNI

### JA3 / JA3S Fingerprinting

- **JA3**: Fingerprints the TLS Client Hello
  - Hash of: `TLS Version + Cipher Suites + Extensions + Elliptic Curves + EC Point Formats`
  - Identifies client application regardless of destination (same malware family produces same JA3 hash).
  - Database: `ja3er.com`
- **JA3S**: Fingerprints the TLS Server Hello  
  - Hash of: `TLS Version + Cipher Suite + Extensions`
  - JA3 + JA3S combination uniquely identifies a client-server pair.
- **JARM**: Active TLS fingerprinting of servers
  - Identifies C2 frameworks (Cobalt Strike, Metasploit, etc.).
  - Sends specially crafted Client Hellos, hashes the responses.

#### Wireshark:
```wireshark
tls.handshake.ja3  (requires plugin or Zeek)
```

## 11.5 SSL/TLS Decryption Methods

1. **Pre-Master Secret Log (SSLKEYLOGFILE)**:
   - Set environment variable `SSLKEYLOGFILE=/path/to/keys.log`
   - Browser logs session keys.
   - Load into Wireshark: `Edit` → `Preferences` → `Protocols` → `TLS` → `Pre-Master Secret log`
2. **Private Key (RSA only, no PFS)**:
   - Only works with RSA key exchange (no DHE/ECDHE).
   - Increasingly rare with modern TLS.
3. **TLS Inspection/MITM Proxy**:
   - Corporate proxies decrypt/re-encrypt HTTPS.
   - Trusted CA cert deployed to endpoints.
   - Tools: Zscaler, Palo Alto SSL Decryption, Squid + SSL Bump.
4. **Endpoint-based**:
   - Capture decrypted traffic on the host itself.
   - Tools: Fiddler, mitmproxy, Burp Suite.

---

# PART 12: EMAIL PROTOCOL ANALYSIS

## 12.1 Email Protocols

- **SMTP (Simple Mail Transfer Protocol)**:
  - Port 25 (server-to-server), 587 (submission with auth), 465 (SMTPS)
  - Commands: `HELO/EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`, `QUIT`
- **POP3 (Post Office Protocol v3)**:
  - Port 110 (cleartext), 995 (SSL/TLS)
  - Downloads emails, typically deletes from server.
- **IMAP (Internet Message Access Protocol)**:
  - Port 143 (cleartext), 993 (SSL/TLS)
  - Syncs emails, keeps on server.

## 12.2 SMTP Analysis

### Suspicious indicators:
- ✦ SMTP on non-standard ports
- ✦ Direct SMTP connections from workstations (not through mail server)
- ✦ SMTP AUTH failures (brute force)
- ✦ Spoofed `MAIL FROM` headers
- ✦ Mismatch between envelope sender and header sender
- ✦ Base64 encoded attachments containing executables
- ✦ SMTP connections to known spam/phishing infrastructure
- ✦ Large volumes of `RCPT TO` (spam distribution)
- ✦ Open relay detection (relaying mail for external domains)

#### Wireshark:
```wireshark
smtp.req.command == "MAIL"
smtp.req.command == "DATA"
smtp.response.code >= 400
imf (Internet Message Format — for email body analysis)
```

## 12.3 Email Header Analysis

### Key headers (bottom-up shows the path):
- `Return-Path`: Envelope sender
- `Received`: Each MTA adds one (trace the route)
- `From`: Display sender (can be spoofed)
- `To`: Recipient
- `Subject`: Subject line
- `Date`: Send time
- `Message-ID`: Unique identifier
- `X-Mailer`: Email client used
- `X-Originating-IP`: Sender's IP (if present)
- `DKIM-Signature`: Domain key authentication
- `Authentication-Results`: SPF, DKIM, DMARC results

### Verification Checks:
- ✦ **SPF**: pass/fail/softfail
- ✦ **DKIM**: pass/fail
- ✦ **DMARC**: pass/fail
- ✦ Originating IP reputation
- ✦ Mismatches in `From` vs. `Return-Path`
- ✦ Received header chain consistency

---

# PART 13: ENCRYPTED TRAFFIC ANALYSIS (ETA)

## 13.1 The Challenge

- ~90% of web traffic is now encrypted (HTTPS).
- Malware increasingly uses TLS for C2 and exfiltration.
- Traditional payload inspection is blind to encrypted content.
- Must use metadata, behavioral analysis, and side-channel information.

## 13.2 What You CAN See in Encrypted Traffic

- ✦ Source/destination IP addresses
- ✦ Source/destination ports
- ✦ Packet sizes and timing
- ✦ TLS handshake details (version, cipher suites, extensions)
- ✦ SNI (Server Name Indication) — domain being accessed
- ✦ Certificate details (subject, issuer, validity, SAN)
- ✦ JA3/JA3S/JARM fingerprints
- ✦ Session duration and data volume
- ✦ Traffic patterns (beaconing, bursts)
- ✦ DNS queries preceding the connection
- ✦ Number of connections and frequency
- ✦ ALPN (Application-Layer Protocol Negotiation) values
- ✦ Encrypted Client Hello (ECH) — emerging, hides SNI too

## 13.3 Encrypted Traffic Analysis Techniques

1. **TLS Metadata Analysis**:
   - Certificate anomalies (self-signed, short-lived, mismatched).
   - Unusual cipher suites.
   - JA3 matching against known malware fingerprints.
   - JA3S matching against known C2 framework responses.
2. **Traffic Pattern Analysis**:
   - Beaconing detection (regular intervals ± jitter).
   - Session duration anomalies.
   - Unusual data volume ratios (large uploads).
   - Connection frequency.
3. **Certificate Analysis**:
   - Certificate Transparency (CT) logs.
   - Newly registered certificates.
   - Free certificate providers (Let's Encrypt) on suspicious domains.
   - Subject Alternative Names (SAN) listing many unrelated domains.
4. **DNS Correlation**:
   - Does a DNS query precede the connection?
   - Direct IP connections without DNS = suspicious.
   - Domain reputation and categorization.
5. **Statistical Analysis**:
   - Byte distribution entropy.
   - Packet size distribution patterns.
   - Inter-arrival time analysis.
   - Machine learning models.
6. **TLS Proxy/Decryption**:
   - Enterprise SSL inspection.
   - `SSLKEYLOGFILE` for controlled environments.

---

# PART 14: LATERAL MOVEMENT DETECTION

## 14.1 What Is Lateral Movement?

After initial compromise, attacker moves through the network to:
- Reach higher-value targets
- Escalate privileges
- Access sensitive data
- Establish persistence

This is the "East-West" traffic that traditional perimeter defenses miss.

## 14.2 Common Lateral Movement Techniques & Network Signatures

### SMB/Windows File Sharing (Ports 445, 139)

- ✦ **PsExec-like activity**: SMB → named pipe creation → service installation.
  - *Zeek*: `smb_mapping.log`, `smb_files.log`
  - *Wireshark*: `smb2.cmd == 5` (Create), look for pipes like `\PSEXESVC`
- ✦ **Admin$ / C$ / IPC$ share access**:
  - Workstation-to-workstation SMB is unusual.
  - `smb2.tree` contains "ADMIN$" or "C$" or "IPC$".
- ✦ **SMB lateral tool transfer**:
  - `.exe`, `.dll`, `.bat`, `.ps1` files being written to remote shares.
  
#### Detection:
- ✦ Any SMB traffic between workstations (not to file servers)
- ✦ SMB to domain controllers on unusual shares
- ✦ New named pipe creation

### Remote Desktop Protocol (RDP) — Port 3389

- ✦ RDP from unusual sources.
- ✦ RDP between workstations (lateral movement).
- ✦ RDP to servers from non-admin workstations.
- ✦ RDP brute force: multiple failed NLA authentications.
- ✦ RDP over non-standard ports (attacker redirects).
- ✦ RDP tunneled through SSH or other protocols.

#### Wireshark:
```wireshark
tcp.dstport == 3389
rdp (protocol dissector)
```

### WMI (Windows Management Instrumentation) — Port 135 + Dynamic

- ✦ Remote process execution via WMI.
- ✦ Initial connection on port 135 (RPC endpoint mapper).
- ✦ Then dynamic high port for actual WMI communication.
- ✦ Workstation-to-workstation WMI is suspicious.

### WinRM (Windows Remote Management) — Ports 5985 (HTTP), 5986 (HTTPS)

- ✦ PowerShell Remoting uses WinRM.
- ✦ Legitimate for admin tools but abused for lateral movement.
- ✦ **Detect**: HTTP traffic on 5985/5986 between workstations.
- ✦ Look for SOAP/XML payloads if unencrypted.

### SSH (Port 22)

- ✦ SSH between internal hosts that don't normally communicate.
- ✦ SSH from Windows hosts (unusual in many environments).
- ✦ SSH tunneling (port forwarding through SSH).
- ✦ Brute force: many failed auth attempts.

### Pass-the-Hash / Pass-the-Ticket (Kerberos)

- ✦ **Network manifestation**: NTLM or Kerberos authentication from unusual hosts.
- ✦ Kerberos TGS requests for unusual services.
- ✦ Overpass-the-hash: Kerberos auth after NTLM hash obtained.
- ✦ **Kerberoasting**: Excessive TGS requests for SPNs.

#### Wireshark:
```wireshark
kerberos
ntlmssp
kerberos.msg_type == 12 (TGS-REQ)
kerberos.msg_type == 13 (TGS-REP)
```

### DCOM (Distributed COM) — Port 135 + Dynamic

- ✦ Used by MMC, Excel DDE, remote COM object activation.
- ✦ Similar to WMI in network behavior (port 135 → dynamic port).

## 14.3 Lateral Movement Detection Strategy

1. Baseline normal internal communications.
2. Alert on new host-to-host communication pairs.
3. Monitor admin tool protocols between workstations.
4. Track authentication patterns (Kerberos/NTLM).
5. Monitor for executable file transfers on SMB.
6. Detect service creation events correlated with network access.
7. Use honeypots/honeytokens as tripwires.
8. Deploy NDR (Network Detection & Response) tools.

---

# PART 15: C2 (COMMAND & CONTROL) TRAFFIC ANALYSIS

## 15.1 C2 Communication Concepts

**C2 Channel**: The communication link between malware and attacker infrastructure.

### C2 Types:
- ✦ **HTTP/HTTPS** — Most common; blends with normal web traffic.
- ✦ **DNS** — DNS tunneling for C2 (stealthier but lower bandwidth).
- ✦ **ICMP** — ICMP tunneling (less common, often blocked).
- ✦ **Custom TCP/UDP** — Raw sockets on unusual ports.
- ✦ **Social Media** — Twitter, Telegram, Pastebin as dead drops.
- ✦ **Cloud Services** — AWS, Azure, Google Drive as C2 relay.
- ✦ **DoH/DoT** — DNS over HTTPS/TLS (evades DNS monitoring).
- ✦ **WebSocket** — Persistent connection disguised as web traffic.
- ✦ **SMTP** — Commands in emails.
- ✦ **Steganography** — Data hidden in images/files.

## 15.2 Beaconing Detection

**Beaconing**: Malware periodically "checks in" with C2 server.

### Characteristics:
- ✦ Regular time intervals (e.g., every 60 seconds).
- ✦ Often with jitter (randomization ± 10-20%).
- ✦ Consistent packet sizes.
- ✦ Usually small request, small response (unless commands are issued).
- ✦ Same destination IP/domain.
- ✦ Continues 24/7 (or during specific hours).

### Detection Methods:
1. **Frequency analysis**: Plot connection times, look for regularity.
2. **Standard deviation** of inter-arrival times (low StdDev = beaconing).
3. **Autocorrelation** of connection timestamps.
4. **Tools**: RITA (Real Intelligence Threat Analytics), AC-Hunter, Zeek + freq analysis scripts.
  
#### RITA analysis (from Zeek logs):
- Beacon score (0-1): Higher = more regular beaconing.
- Data size consistency.
- Connection count.
- Duration analysis.

#### Wireshark approach:
1. Filter to specific destination: `ip.dst == x.x.x.x`
2. `Statistics` → `IO Graph` → plot over time.
3. Look for regular spikes.
4. Check `tcp.stream` to examine individual sessions.

## 15.3 Common C2 Frameworks & Their Network Signatures

### Cobalt Strike

Default indicators (can be customized by operators):
- ✦ **Default HTTPS certificate**: serial number patterns.
- ✦ **Default named pipes**: `\postex_*`, `\MSSE-*`.
- ✦ **HTTP beacons**: `checksum8` or `checksum8s` in URI.
- ✦ **JA3/JA3S fingerprints**: specific to Cobalt Strike.
- ✦ **JARM fingerprint**: `07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d`.
- ✦ Default HTTP headers and response structure.
- ✦ Malleable C2 profiles can change all these indicators.

#### Detection approach:
- JARM scanning of suspicious HTTPS servers.
- JA3S matching against known CS fingerprints.
- Certificate analysis.
- Behavior: beaconing patterns, data size ratios.

### Metasploit / Meterpreter

- ✦ **Default ports**: 4444 (reverse TCP), 8080 (HTTP).
- ✦ **Meterpreter staged**: small initial payload downloads larger stage.
- ✦ **HTTP staging**: `GET /random-4-char-uri`.
- ✦ Known TLS certificates.
- ✦ JARM fingerprints for Metasploit handler.

### Sliver

- ✦ HTTP/HTTPS/DNS/mTLS/WireGuard C2.
- ✦ Specific JA3 fingerprints.
- ✦ JARM fingerprint differs from Cobalt Strike.
- ✦ Default HTTP patterns.

### PowerShell Empire / Covenant / Brute Ratel / Mythic

Each has characteristic:
- ✦ HTTP request patterns (URIs, headers, cookies).
- ✦ JA3/JA3S fingerprints.
- ✦ Beaconing behavior.
- ✦ Data encoding methods (base64, custom encryption).

## 15.4 C2 Over DNS (Detailed)

### How it works:
```text
Malware → DNS Query: encoded-data.c2domain.com → Internal DNS → 
External DNS → Attacker's Authoritative NS → Response with commands
```
- **Uplink (data exfil)**: Encoded in subdomain labels (e.g., `aBcDeFg123.x7yZ.c2domain.com`).
- **Downlink (commands)**: Encoded in TXT, CNAME, or A record responses.

### Detection:
- ✦ **Volume**: Excessive DNS queries to a single domain.
- ✦ **Length**: Subdomain labels >30 characters.
- ✦ **Entropy**: High randomness in subdomain names.
- ✦ **Record types**: Unusual TXT, NULL, CNAME queries.
- ✦ **Response size**: Abnormally large DNS responses.
- ✦ **Timing**: Regular query intervals.
- ✦ **Resolver**: Queries bypassing internal DNS (going directly to external).

## 15.5 C2 Over HTTPS

### Why attackers love HTTPS C2:
- Blends with normal web traffic.
- Encrypted payload hides content.
- Port 443 almost always allowed outbound.
- CDN/domain fronting can hide true destination.

### Detection without decryption:
- ✦ JA3 fingerprinting.
- ✦ Certificate analysis.
- ✦ SNI mismatch with certificate CN.
- ✦ Beaconing patterns.
- ✦ Direct IP connections (no SNI, no prior DNS).
- ✦ Data volume anomalies.
- ✦ Unusual TLS versions or cipher suites.
- ✦ Session duration analysis.
- ✦ Newly registered domains / recently issued certificates.

### Domain Fronting:
- SNI shows legitimate domain (e.g., `cdn.google.com`).
- HTTP Host header (encrypted) shows real C2 domain.
- Only detectable with TLS decryption.
- Most CDNs have now blocked this technique.

---

# PART 16: DATA EXFILTRATION DETECTION

## 16.1 Exfiltration Channels

- ✦ HTTP/HTTPS uploads (POST requests, multipart uploads)
- ✦ DNS tunneling (slow but stealthy)
- ✦ FTP/SFTP/SCP transfers
- ✦ Email (SMTP with attachments)
- ✦ Cloud storage (Dropbox, Google Drive, OneDrive, Mega)
- ✦ SMB/CIFS to external shares
- ✦ ICMP tunneling
- ✦ Steganography (data hidden in images/documents)
- ✦ Encrypted channels on non-standard ports
- ✦ USB/physical (not network-detectable)
- ✦ Print/fax (not network-detectable for physical printers)
- ✦ Bluetooth/Wi-Fi direct (not visible on wired network)

## 16.2 Network Indicators of Exfiltration

- ✦ Large outbound data transfers (especially to new/unusual destinations)
- ✦ Uploads significantly exceeding downloads to a destination
- ✦ Data transfers during off-hours
- ✦ Connections to newly registered domains
- ✦ Connections to known file-sharing/cloud storage services
- ✦ Unusual protocols for the environment (e.g., FTP from a workstation)
- ✦ Encrypted traffic on non-standard ports
- ✦ Compressed/archived files being transferred (`.zip`, `.7z`, `.rar`)
- ✦ Data trickling out slowly over extended periods (low-and-slow)
- ✦ DNS queries with high entropy subdomain names (DNS exfil)
- ✦ Large ICMP packets
- ✦ Unusual volume of email attachments from a single host

## 16.3 Exfiltration Detection Strategies

1. **NetFlow/metadata analysis**:
   - Identify top uploaders (bytes sent >> bytes received).
   - Baseline outbound data volumes per host.
   - Alert on deviations.
2. **DLP (Data Loss Prevention) integration**:
   - Content inspection for sensitive data patterns.
   - Credit card numbers, SSNs, keywords.
3. **Proxy log analysis**:
   - Cloud storage access patterns.
   - Large uploads to uncategorized URLs.
   - Base64-encoded POST bodies.
4. **DNS monitoring**:
   - Query volume per domain.
   - Subdomain length and entropy.
5. **Full packet capture**:
   - Extract and inspect uploaded files.
   - Identify data encoding (base64, XOR, custom).
6. **Behavioral analytics**:
   - User normally transfers 50MB/day, suddenly transfers 5GB.
   - Access to file shares never accessed before, followed by outbound transfer.

---

# PART 17: NETWORK-BASED ATTACK PATTERNS

## 17.1 Reconnaissance

### Port Scanning:
- **TCP SYN Scan**: SYN → SYN-ACK (open) or RST (closed).
  - *Nmap*: `nmap -sS`
  - *Network*: Many SYN packets to different ports, no ACK completion.
- **TCP Connect Scan**: Full handshake.
  - *Nmap*: `nmap -sT`
  - *Network*: Full handshakes followed by immediate RST.
- **TCP FIN Scan**: FIN → no response (open) or RST (closed).
  - *Network*: FIN packets with no prior connection.
- **TCP XMAS Scan**: FIN+PSH+URG → no response (open) or RST (closed).
  - *Network*: Unusual flag combinations.
- **TCP NULL Scan**: No flags → no response (open) or RST (closed).
  - *Network*: TCP packets with no flags set.
- **UDP Scan**: UDP → no response (open|filtered) or ICMP port unreachable (closed).
  - *Nmap*: `nmap -sU`
  - *Network*: UDP to many ports, ICMP unreachable responses.
- **Idle/Zombie Scan**: Uses third party's IP ID sequence.
  - *Nmap*: `nmap -sI`
  - *Network*: Very hard to detect — appears to come from zombie host.

### Host Sweep:
- ICMP Echo to many hosts (ping sweep).
- TCP SYN to port 80/443 to many hosts.
- ARP requests to many IPs in subnet.
- *Network*: One source → many destinations on same port.

### Service Enumeration:
- Banner grabbing on discovered ports.
- SMB enumeration (port 445): shares, users, groups.
- SNMP enumeration (port 161): community string guessing.
- LDAP enumeration (port 389): directory queries.
- RPC enumeration (port 111/135).

### Detection:
- ✦ Many connection attempts from one source to many destinations/ports.
- ✦ High rate of RST or ICMP unreachable responses.
- ✦ Unusual TCP flag combinations.
- ✦ Sequential port access patterns.
- ✦ IDS signatures for known scanning tools.

## 17.2 Man-in-the-Middle (MitM) Attacks

### ARP Spoofing MitM:
- ✦ Gratuitous ARP replies.
- ✦ ARP table showing duplicate MACs for different IPs.
- ✦ Tools: `ettercap`, `arpspoof`, `bettercap`.

### DNS Spoofing MitM:
- ✦ False DNS responses beating legitimate ones.
- ✦ *Detection*: Duplicate DNS responses with different answers.

### SSL Stripping:
- ✦ Downgrade HTTPS to HTTP.
- ✦ Attacker proxies between victim (HTTP) and server (HTTPS).
- ✦ *Detection*: HTTP connections where HTTPS is expected.

### LLMNR/NBT-NS Poisoning:
- ✦ Respond to broadcast name resolution requests.
- ✦ Capture NTLM hashes.
- ✦ Tools: `Responder`, `Inveigh`.
- ✦ *Detection*: LLMNR (port 5355) or NBT-NS (port 137) responses from unexpected hosts.

## 17.3 Denial of Service (DoS/DDoS)

### Volumetric Attacks:
- ✦ UDP Flood
- ✦ ICMP Flood
- ✦ DNS Amplification
- ✦ NTP Amplification (monlist)
- ✦ SSDP Amplification
- ✦ Memcached Amplification
- ✦ CLDAP Amplification (port 389)

### Protocol Attacks:
- ✦ SYN Flood (exhaust connection tables)
- ✦ Ping of Death (oversized ICMP)
- ✦ Smurf Attack (ICMP to broadcast with spoofed source)
- ✦ Fragmentation attacks (teardrop)
- ✦ TCP RST attack

### Application Layer (L7) Attacks:
- ✦ HTTP Flood (GET/POST flood)
- ✦ Slowloris (keep connections open with partial headers)
- ✦ Slow POST (send POST body very slowly)
- ✦ DNS query flood

### Detection:
- ✦ Sudden massive spike in traffic volume.
- ✦ Single source or distributed sources hitting one target.
- ✦ High volume of SYN without ACK completion.
- ✦ Amplification: many large responses to a victim from reflectors.
- ✦ Application slowdown correlated with traffic patterns.

## 17.4 Brute Force Attacks (Network Perspective)

### Targets:
- ✦ **SSH (port 22)**: Many failed auth attempts.
- ✦ **RDP (port 3389)**: NLA failures.
- ✦ **FTP (port 21)**: `530 Login incorrect` responses.
- ✦ **SMTP AUTH**: `535 Authentication failed`.
- ✦ **Web login**: POST to login page with different credentials, 401/403 responses.
- ✦ **Kerberos**: Multiple AS-REQ failures (`KDC_ERR_PREAUTH_FAILED`).
- ✦ **LDAP Bind**: Failed bind attempts.

### Detection:
- ✦ Many short-duration connections to auth-related ports.
- ✦ High volume of failed authentication responses.
- ✦ Same source, many attempts in short time.
- ✦ Credential stuffing: different source IPs, same target.
- ✦ Password spraying: few attempts per account, many accounts.

## 17.5 Exploitation

### Network signatures of exploitation:
- ✦ Shellcode in packet payload (NOP sleds: `0x90909090`).
- ✦ Buffer overflow patterns (long strings of repeated characters).
- ✦ Known exploit signatures (IDS/IPS rules).
- ✦ Unusual application behavior after specific request.
- ✦ Connection followed by reverse shell (outbound connection on unusual port).
- ✦ **EternalBlue/MS17-010**: SMBv1 exploit → unusual SMB behavior on port 445.
- ✦ **Log4Shell**: `${jndi:ldap://...}` in any protocol (HTTP headers, etc.).
- ✦ **PrintNightmare**: Unusual DCE/RPC calls to `spoolss`.

---

# PART 18: IDS/IPS & SIGNATURE ANALYSIS

## 18.1 IDS vs IPS

- **IDS (Intrusion Detection System)**:
  - Passive monitoring (out-of-band via SPAN/TAP).
  - Generates alerts only — does not block.
  - No risk of causing outage.
- **IPS (Intrusion Prevention System)**:
  - Inline deployment (traffic passes through it).
  - Can block/drop malicious traffic.
  - Risk of false positives causing legitimate traffic disruption.

### Detection Methods:
1. **Signature-based**: Pattern matching against known attacks.
2. **Anomaly-based**: Deviation from baseline (statistical/ML).
3. **Policy-based**: Violation of defined rules.
4. **Protocol analysis**: Violation of protocol standards (RFC).
5. **Heuristic**: Behavioral patterns suggesting malicious activity.

## 18.2 Snort/Suricata Rule Anatomy

```text
action protocol src_ip src_port -> dst_ip dst_port (options)
```

### Example:
```text
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (
  msg:"ET EXPLOIT Possible MS17-010 EternalBlue";
  flow:to_server,established;
  content:"|00|"; depth:1;
  content:"|FF|SMB"; distance:3; within:4;
  content:"|23 00 00 00 07 00 5c|PIPE|5c 00|"; distance:0;
  sid:2024218; rev:4;
  classtype:attempted-admin;
  reference:cve,2017-0144;
)
```

## 18.3 Rule Components Explained

- **Action**:
  - `alert` — Generate alert
  - `log` — Log the packet
  - `pass` — Ignore the packet
  - `drop` — Block and log (IPS mode)
  - `reject` — Block, log, and send RST/ICMP unreachable
- **Protocol**: `tcp`, `udp`, `icmp`, `ip`, `http`, `dns`, `tls`, `smb`, etc. (Suricata protocol keywords)
- **Variables**:
  - `$HOME_NET` — Your internal network (defined in config)
  - `$EXTERNAL_NET` — Everything else (usually `!$HOME_NET`)
  - `$HTTP_PORTS` — Web server ports
  - `$DNS_SERVERS` — Your DNS servers
- **Direction**:
  - `->` — Unidirectional (src to dst)
  - `<>` — Bidirectional
- **Key Options**:
  - `msg:` — Alert message
  - `sid:` — Signature ID (unique)
  - `rev:` — Revision number
  - `classtype:` — Attack category
  - `priority:` — Severity (1-4, 1=highest)
  - `reference:` — External reference (CVE, URL)
- **Content Matching**:
  - `content:` — Pattern to match (text or hex with `|xx xx|`)
  - `nocase` — Case-insensitive
  - `depth:` — Search only first N bytes
  - `offset:` — Start searching from byte N
  - `distance:` — Distance from previous match
  - `within:` — Search within N bytes of previous match
- **Flow**:
  - `flow:to_server,established` — Match established connections to server
  - `flow:to_client,established` — Match server responses
  - `flow:from_server`
- **Protocol-Specific**:
  - `http_method`, `http_uri`, `http_header`, `http_client_body`
  - `dns_query`
  - `tls_cert_subject`, `tls_sni`
  - `file_data` (normalized HTTP response body)
- **Thresholding**:
  - `threshold:type both,track by_src,count 10,seconds 60` (Alert once if 10+ events from same source in 60 seconds)

## 18.4 Understanding IDS Alerts in SOC

### Alert Triage Process:
1. Read the alert message and signature.
2. Check the source and destination IPs.
3. Determine if it's inbound or outbound.
4. Check if the targeted service/port is relevant.
5. Look at the raw packet / payload.
6. Correlate with other alerts or logs.
7. Check threat intelligence for the source/destination.
8. Determine: **True Positive**, **False Positive**, or **Benign True Positive**.

### False Positive Causes:
- ✦ Overly broad signatures.
- ✦ Legitimate traffic matching patterns (e.g., binary downloads).
- ✦ Misconfigured variables (`$HOME_NET`, `$EXTERNAL_NET`).
- ✦ Encrypted traffic being matched on fragments.
  
### True Positive Indicators:
- ✦ Alert matches known vulnerability for target system.
- ✦ Subsequent suspicious activity from same hosts.
- ✦ Payload matches known exploit code.
- ✦ Source has bad reputation.
- ✦ Target responds abnormally after the alert.

## 18.5 Common Rule Sources

- ✦ **Emerging Threats (ET) Open**: Free, community-maintained.
- ✦ **Emerging Threats Pro**: Commercial, more comprehensive.
- ✦ **Snort Community Rules**: Free Snort rules.
- ✦ **Snort Subscriber (Talos)**: Commercial Snort rules.
- ✦ **Suricata OISF Rules**: Suricata-specific.
- ✦ **Custom Rules**: Organization-specific.
- ✦ **MITRE ATT&CK mapped rules**: Mapped to TTPs.

---

# PART 19: NETFLOW / sFlow / IPFIX ANALYSIS

## 19.1 What Is NetFlow?

**NetFlow**: Cisco-developed protocol for collecting IP traffic metadata. Created by routers/switches/firewalls — NOT full packet capture.

### A NetFlow record contains:
- ✦ Source IP
- ✦ Destination IP
- ✦ Source port
- ✦ Destination port
- ✦ IP protocol
- ✦ Type of Service (ToS)
- ✦ Input interface
- ✦ Bytes transferred
- ✦ Packets count
- ✦ Start/end timestamps
- ✦ TCP flags (cumulative)
- ✦ Next-hop IP
- ✦ Source/destination AS numbers
- ✦ Source/destination prefix mask

### Versions:
- **NetFlow v5**: Fixed format, IPv4 only.
- **NetFlow v9**: Template-based, extensible.
- **IPFIX**: IETF standard based on NetFlow v9.
- **sFlow**: Sampling-based (captures 1 in N packets), includes packet headers.
- **jFlow**: Juniper's implementation.
- **NetStream**: Huawei's implementation.

## 19.2 NetFlow vs PCAP

| Feature | NetFlow | PCAP |
| :--- | :--- | :--- |
| **Depth** | Metadata only | Full content |
| **Storage** | ~1% of PCAP | 100% of traffic |
| **Duration** | Months/years | Hours/days |
| **Privacy** | Less concern | Contains content |
| **Detection** | Patterns/volumes | Signatures/content |
| **Speed** | Fast queries | Slower analysis |
| **Deployment** | On existing infra | Needs TAPs/SPAN |

## 19.3 NetFlow Analysis Use Cases

- ✦ **Beaconing detection**: Regular connections, consistent sizes.
- ✦ **Data exfiltration**: Unusual outbound data volumes.
- ✦ **Port scanning**: One source → many destinations/ports.
- ✦ **DDoS detection**: Massive flow counts to single destination.
- ✦ **Lateral movement**: New internal communication pairs.
- ✦ **Anomaly detection**: Deviations from baseline traffic patterns.
- ✦ **Long connections**: C2 channels that stay connected for hours.
- ✦ **Protocol anomalies**: Unusual protocols or port usage.
- ✦ **Top talkers**: Identify most active hosts.
- ✦ **Forensic timeline**: When did communication start/stop?

## 19.4 NetFlow Analysis Tools

- ✦ **SiLK (System for Internet-Level Knowledge)**:
  - Free suite from CERT/CC.
  - `rwfilter`, `rwstats`, `rwcount`, `rwuniq`, `rwsort`.
  - Command-line based, powerful for large datasets.
- ✦ **nfdump / nfsen**:
  - `nfdump`: CLI analysis of NetFlow data.
  - `nfsen`: Web frontend for `nfdump`.
- ✦ **Elastic Stack (ELK)**:
  - Logstash: Ingest NetFlow via input plugin.
  - Elasticsearch: Store and index.
  - Kibana: Visualize and explore.
- ✦ **Splunk**:
  - Splunk Stream or NetFlow add-ons.
  - SPL queries for flow analysis.
- ✦ **Kentik**: Commercial NetFlow analytics platform.
- ✦ **ntopng**: Open-source network traffic monitoring.

### SiLK Example Commands

```bash
# Find all flows from a specific IP
rwfilter --saddress=192.168.1.100 --pass=stdout data.rw | rwcut

# Top 10 destination IPs by bytes
rwfilter --type=all --pass=stdout data.rw | rwstats --fields=dip --bytes --count=10

# Find flows to port 4444 (common reverse shell)
rwfilter --dport=4444 --pass=stdout data.rw | rwcut

# Long-duration connections (>1 hour)
rwfilter --duration=3600- --pass=stdout data.rw | rwcut

# Large transfers (>100MB)
rwfilter --bytes=104857600- --pass=stdout data.rw | rwcut --fields=sip,dip,sport,dport,bytes,duration

# Count unique source IPs connecting to a destination
rwfilter --daddress=10.0.0.5 --pass=stdout data.rw | rwuniq --fields=sip --count
```

---

# PART 20: LOG CORRELATION WITH NETWORK DATA

## 20.1 Correlation Sources

Network data alone tells part of the story. Correlate with:
- ✦ **Firewall logs**: Allowed/denied connections, NAT translations.
- ✦ **Proxy logs**: Full URLs, user agents, response codes, user identity.
- ✦ **DNS logs**: Query/response pairs (Zeek `dns.log`, Windows DNS debug log).
- ✦ **DHCP logs**: IP-to-MAC-to-hostname mapping at specific times.
- ✦ **Active Directory logs**: Authentication events (4624, 4625, 4648, 4768, 4769, 4771).
- ✦ **VPN logs**: Remote access connections, source IPs, user identity.
- ✦ **Endpoint logs**: Process creation, network connections (Sysmon EventID 3).
- ✦ **Email gateway logs**: Sender, recipient, attachment hashes, URLs.
- ✦ **Cloud logs**: AWS CloudTrail, Azure Activity, GCP Audit.
- ✦ **WAF logs**: Web attacks detected/blocked.
- ✦ **SIEM**: Central correlation platform.

## 20.2 Common Correlation Scenarios

### Scenario 1: Phishing → Malware Download → C2
- **Email gateway**: Phishing email with URL received by `user@company.com`.
- **Proxy log**: `user@company.com` accessed URL, downloaded `malicious.exe`.
- **Endpoint**: `malicious.exe` process created, spawned PowerShell.
- **DNS**: New queries to `c2domain.com` from user's workstation.
- **NetFlow**: Regular beaconing to `c2domain.com` IP every 60 seconds.
- **Firewall**: Outbound connection to c2 IP on port 443 allowed.

### Scenario 2: Brute Force → Compromise → Lateral Movement
- **Firewall**: Many SSH connections from external IP to DMZ server.
- **IDS alert**: SSH brute force detected.
- **Auth logs**: Multiple failed SSH logins, then success.
- **NetFlow**: DMZ server now initiating SMB connections to internal servers.
- **AD logs**: Unusual service account authentication from DMZ server.
- **Endpoint**: PsExec service installed on internal server.

### Scenario 3: Insider Threat Data Exfiltration
- **DLP**: Sensitive file access by user.
- **NetFlow**: Large upload to cloud storage IP.
- **Proxy**: POST requests to `mega.nz` from user's workstation.
- **Endpoint**: Zip utility creating archive, then upload via browser.
- **Badge system**: User accessed building at unusual hours.

## 20.3 SIEM Queries & Correlation Rules

Common SIEM correlation rules for network analysis:

```text
1. Port Scan Detection:
   IF source_ip makes >100 connections to different destination ports
   on same destination_ip within 60 seconds
   THEN alert "Port Scan Detected"

2. Beaconing Detection:
   IF source_ip connects to same destination_ip/port
   >50 times with similar inter-arrival times (low std deviation)
   over 24 hours
   THEN alert "Possible C2 Beaconing"

3. Data Exfiltration:
   IF internal_ip uploads >500MB to external_ip in 1 hour
   AND no prior download of similar size
   THEN alert "Potential Data Exfiltration"

4. Lateral Movement:
   IF workstation_ip initiates SMB/RDP/WMI to another workstation_ip
   AND this communication pair is not in baseline
   THEN alert "Potential Lateral Movement"

5. DNS Tunneling:
   IF internal_ip queries >100 unique subdomains of same domain in 1 hour
   AND average subdomain length > 30 characters
   THEN alert "Potential DNS Tunneling"
```

---

# PART 21: WIRELESS NETWORK ANALYSIS

## 21.1 Wireless Standards

- **802.11a** — 5 GHz, 54 Mbps
- **802.11b** — 2.4 GHz, 11 Mbps
- **802.11g** — 2.4 GHz, 54 Mbps
- **802.11n** — 2.4/5 GHz, 600 Mbps (Wi-Fi 4)
- **802.11ac** — 5 GHz, 6.9 Gbps (Wi-Fi 5)
- **802.11ax** — 2.4/5/6 GHz, 9.6 Gbps (Wi-Fi 6/6E)

## 21.2 Wireless Security Protocols

- **WEP**: Wired Equivalent Privacy — BROKEN, trivially crackable (RC4).
- **WPA**: Wi-Fi Protected Access — TKIP, improved but still vulnerable.
- **WPA2**: AES-CCMP — Current standard, vulnerable to KRACK, PMKID attacks.
- **WPA3**: SAE (Simultaneous Authentication of Equals) — improved, resistant to offline dictionary attacks (Dragonblood vulnerabilities exist).
- **WPA2-Enterprise**: 802.1X + RADIUS — per-user authentication.

## 21.3 Wireless Attacks

- ✦ **Evil Twin**: Rogue AP mimicking legitimate SSID.
- ✦ **Deauthentication Attack**: Force clients to disconnect (802.11 deauth frames).
- ✦ **WPA2 Handshake Capture**: Capture 4-way handshake → offline cracking.
- ✦ **PMKID Attack**: Capture PMKID from AP without full handshake → crack offline.
- ✦ **KARMA/Hostapd-Mana**: Respond to any probe request as the requested SSID.
- ✦ **Rogue AP**: Unauthorized access point on network.
- ✦ **Wi-Fi Pineapple**: Hardware tool for wireless attacks.

### Detection:
- ✦ WIDS/WIPS (Wireless Intrusion Detection/Prevention System).
- ✦ Monitor for rogue APs (unauthorized BSSIDs).
- ✦ Detect deauth floods.
- ✦ 802.1X NAC for wired and wireless.
- ✦ Regular wireless surveys.

## 21.4 Wireless Capture

**Monitor Mode**: Capture all wireless frames (not just your network).
- Required for wireless analysis.
- Tools: Wireshark, Aircrack-ng suite, Kismet.
- Need compatible wireless adapter (Alfa, etc.).

### 802.11 Frame Types:
- **Management**: Beacon, Probe Request/Response, Authentication, Association, Deauthentication, Disassociation.
- **Control**: RTS, CTS, ACK.
- **Data**: Actual data frames.

### Wireshark filters:
```wireshark
wlan.fc.type == 0       # Management frames
wlan.fc.type == 1       # Control frames
wlan.fc.type == 2       # Data frames
wlan.fc.type_subtype == 0x0c  # Deauthentication
wlan.ssid == "CompanyWiFi"
wlan.bssid == aa:bb:cc:dd:ee:ff
```

---

# PART 22: CLOUD & VIRTUAL NETWORK ANALYSIS

## 22.1 Cloud Networking Concepts

- **VPC (Virtual Private Cloud)**:
  - Isolated virtual network in cloud. Subnets, route tables, internet gateways, NAT gateways.
- **Security Groups (AWS) / NSGs (Azure)**:
  - Virtual firewalls for instances/VMs. Stateful rules based on IP, port, protocol.
- **NACLs (Network ACLs)**:
  - Stateless rules at subnet level.
- **VPC Peering**:
  - Direct connection between two VPCs.
- **Transit Gateway**:
  - Hub-and-spoke connectivity between VPCs.
- **PrivateLink / Private Endpoint**:
  - Access cloud services without traversing public internet.
- **VPN Gateway**:
  - Site-to-site or point-to-site VPN to cloud.

## 22.2 Cloud Network Monitoring

### AWS:
- ✦ **VPC Flow Logs**: NetFlow-like records for VPC.
  - Fields: `srcaddr`, `dstaddr`, `srcport`, `dstport`, `protocol`, `packets`, `bytes`, `start`, `end`, `action` (ACCEPT/REJECT), `log-status`.
- ✦ **CloudTrail**: API-level logging (control plane).
- ✦ **GuardDuty**: Threat detection service (analyzes flow logs, DNS, CloudTrail).
- ✦ **Traffic Mirroring**: Full packet capture in VPC.
- ✦ Route 53 DNS query logging.

### Azure:
- ✦ NSG Flow Logs: Flow records for NSGs.
- ✦ Azure Network Watcher: Packet capture, connection troubleshooting.
- ✦ Azure Sentinel: Cloud SIEM.
- ✦ Azure Firewall logs.

### GCP:
- ✦ VPC Flow Logs: Similar to AWS.
- ✦ Packet Mirroring: Full capture.
- ✦ Cloud IDS (powered by Palo Alto).
- ✦ DNS Logging.

## 22.3 Cloud-Specific Threats

- ✦ Misconfigured security groups (`0.0.0.0/0` inbound).
- ✦ Exposed management ports (SSH, RDP) to internet.
- ✦ S3 bucket / Azure blob data exposure.
- ✦ Metadata service exploitation (`169.254.169.254` → SSRF to steal instance credentials).
- ✦ Lateral movement between VPCs via peering/transit.
- ✦ Cloud-native C2 using cloud services (Lambda, Functions, S3).
- ✦ Cryptojacking (unauthorized compute usage).
- ✦ Container escape → host network access.
- ✦ Kubernetes API exposure.

## 22.4 Container & Kubernetes Network Analysis

### Container Networking:
- ✦ Bridge networking (`docker0`).
- ✦ Overlay networks (Flannel, Calico, Weave).
- ✦ Pod-to-pod communication.
- ✦ Service mesh (Istio, Linkerd) — mTLS between services.

### Kubernetes-Specific:
- ✦ **NetworkPolicies**: Define allowed pod-to-pod communication.
- ✦ Ingress/Egress controllers: L7 traffic management.
- ✦ Service discovery via CoreDNS/KubeDNS.
- ✦ Node-to-node communication.
  
### Monitoring:
- ✦ **Cilium**: eBPF-based networking and observability.
- ✦ **Calico**: Network policy enforcement + flow logs.
- ✦ **Falco**: Runtime security monitoring.
- ✦ Container-level network captures.

---

# PART 23: ZERO TRUST & MICRO-SEGMENTATION

## 23.1 Zero Trust Principles

"Never trust, always verify"

### Core tenets:
1. Verify explicitly (authenticate/authorize every request).
2. Use least privilege access.
3. Assume breach (minimize blast radius).

### Network implications:
- ✦ No implicit trust based on network location.
- ✦ Internal network treated same as external.
- ✦ Every connection authenticated and authorized.
- ✦ Continuous validation throughout session.
- ✦ Granular access control per application/service.

## 23.2 Micro-Segmentation

**Definition**: Dividing network into smallest possible segments, each with its own security policies.

### Implementation:
- ✦ Host-based firewalls with central policy management.
- ✦ Software-defined networking (SDN).
- ✦ Network virtualization platforms (VMware NSX, Cisco ACI).
- ✦ Identity-based segmentation (per user/app, not per IP).
- ✦ Cloud security groups (per instance/container).

### SOC Impact:
- ✦ More granular visibility into east-west traffic.
- ✦ Policy violations generate alerts.
- ✦ Reduced lateral movement capability for attackers.
- ✦ More complex environment to monitor.
- ✦ Need for identity-aware network analysis.

---

# PART 24: THREAT INTELLIGENCE & NETWORK IoCs

## 24.1 Network-Based Indicators of Compromise

### Types of Network IoCs:
- ✦ IP addresses (C2 servers, known-bad infrastructure)
- ✦ Domain names (C2 domains, phishing domains, DGA domains)
- ✦ URLs (malware distribution, exploit kit landing pages)
- ✦ SSL/TLS certificates (JA3/JA3S hashes, certificate hashes)
- ✦ JARM fingerprints (server-side TLS fingerprints)
- ✦ User-Agent strings (known malware UAs)
- ✦ HTTP headers/patterns (specific C2 framework patterns)
- ✦ DNS patterns (specific DGA algorithms)
- ✦ Port/protocol combinations
- ✦ SNORT/Suricata signatures
- ✦ YARA rules (for file/payload matching)

## 24.2 Threat Intelligence Feeds

### Free:
- ✦ **AlienVault OTX (Open Threat Exchange)**
- ✦ **Abuse.ch** (URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker)
- ✦ **CIRCL MISP**
- ✦ Emerging Threats Open Rules
- ✦ PhishTank
- ✦ Spamhaus
- ✦ VirusTotal (limited free)
- ✦ CISA Alerts / IoCs
- ✦ Tor exit node lists
- ✦ OpenPhish
- ✦ Blocklist.de

### Commercial:
- ✦ Recorded Future
- ✦ CrowdStrike Falcon Intelligence
- ✦ Mandiant/Google Threat Intelligence
- ✦ ThreatConnect
- ✦ Anomali ThreatStream
- ✦ Intel 471
- ✦ Group-IB
- ✦ Palo Alto Unit 42

### Standards:
- ✦ **STIX** (Structured Threat Information eXpression) — Format.
- ✦ **TAXII** (Trusted Automated eXchange of Indicator Information) — Transport.
- ✦ **MISP** — Platform for sharing threat intelligence.
- ✦ **OpenIOC** — Mandiant's IoC format.

## 24.3 Using Threat Intelligence in Network Analysis

1. **IoC Matching**:
   - Match network traffic against known indicators.
   - Automated via SIEM, IDS rules, firewall feeds.
   - Real-time and retrospective (historical data search).
2. **Context Enrichment**:
   - Add context when an IoC matches:
     → Attribution (which threat actor/campaign)
     → TTP mapping (MITRE ATT&CK)
     → Confidence level
     → First/last seen dates
     → Related IoCs
3. **Hunting**:
   - Proactively search for indicators in historical data.
   - Use TTP-based hunting (behavior patterns, not just indicators).
   - Hypothesis-driven: "What would traffic look like if APT28 were in our network?"
4. **IoC Lifecycle**:
   - IoCs have a shelf life. IPs change quickly (hours-days), domains last longer but get taken down.
   - TTPs are the most durable intelligence.
   - Regularly update and expire old IoCs.

## 24.4 Pivoting from IoCs

Starting with one IoC, discover related infrastructure:
- **IP** → reverse DNS → other domains on same IP
- **IP** → ASN → other IPs in same ASN/subnet
- **Domain** → WHOIS → registrant → other domains by same registrant
- **Domain** → passive DNS → historical IPs → other domains on same IP
- **Certificate** → SHA256 → other hosts using same cert
- **JA3 hash** → other connections with same client fingerprint
- **JARM hash** → other servers with same configuration

### Tools:
- ✦ VirusTotal (VT Graph)
- ✦ PassiveTotal / RiskIQ
- ✦ Shodan / Censys / ZoomEye
- ✦ DNSdumpster
- ✦ SecurityTrails
- ✦ Maltego
- ✦ MISP
- ✦ TheHive + Cortex

---

# PART 25: ADVANCED FORENSIC TECHNIQUES

## 25.1 Full Packet Capture Forensics

### Collection:
- ✦ **Size estimation**: 1 Gbps link ≈ 10-15 TB/day at full utilization.
- ✦ **Retention**: Prioritize critical segments, retain days-weeks.
- ✦ **Timestamping**: NTP synchronization critical (nanosecond precision ideal).
- ✦ **Chain of custody**: Hash PCAP files (MD5/SHA256), document handling.

### Tools:
- ✦ **Arkime (Moloch)**: Index and search PCAPs at scale.
- ✦ **Stenographer**: High-speed packet capture (Google).
- ✦ **netsniff-ng**: High-performance capture.
- ✦ **Zeek**: Generate structured logs from PCAPs.

### Extraction:
- ✦ **File carving** from PCAPs (NetworkMiner, Wireshark export objects, foremost).
- ✦ **Credential extraction** (cleartext protocols: HTTP, FTP, Telnet, POP3).
- ✦ **Session reconstruction** (follow TCP stream in Wireshark).
- ✦ Timeline construction from packet timestamps.
- ✦ Metadata extraction (HTTP headers, DNS queries, TLS certificates).

## 25.2 Network Forensics Methodology

1. **Preparation**:
   - Ensure capture infrastructure is in place.
   - Time synchronization verified.
   - Capture storage capacity planned.
2. **Identification**:
   - What event triggered the investigation?
   - What time window is relevant?
   - Which network segments are relevant?
   - What IoCs do we have?
3. **Collection**:
   - Preserve existing captures.
   - Start additional capture if ongoing.
   - Collect related logs (firewall, proxy, DNS, IDS).
   - Document everything.
4. **Analysis**:
   - *Phase 1: High-level overview*: Protocol hierarchy, conversations/top talkers, endpoints/geographic distribution, timeline of events.
   - *Phase 2: Targeted analysis*: Filter on IoCs, follow suspicious streams, extract transferred files, decode encoded content, map communication patterns.
   - *Phase 3: Deep dive*: Reconstruct attack timeline, identify all compromised hosts, determine data accessed/exfiltrated, identify attacker TTPs, correlate with host forensics.
5. **Reporting**:
   - Executive summary, technical findings, timeline, IoCs, recommendations.

## 25.3 Protocol Anomaly Detection

Protocols have defined standards (RFCs). Deviations can indicate:
- ✦ Tunneling (data hidden in legitimate protocols).
- ✦ Evasion (confusing IDS/IPS).
- ✦ Exploitation (protocol implementation bugs).
- ✦ Custom/modified protocols (malware C2).

### Examples:
- ✦ **DNS**: Queries >255 chars, non-printable chars in labels, unusual record types.
- ✦ **HTTP**: Invalid methods, excessively long headers, non-RFC-compliant responses.
- ✦ **ICMP**: Non-zero payload in echo requests (tunneling).
- ✦ **TCP**: Invalid flag combinations, non-zero urgent pointer without URG flag.
- ✦ **SMB**: Protocol version mismatches, unusual command sequences.
- ✦ **TLS**: Version downgrade, invalid certificate chains, unusual extensions.

*Note: Zeek is excellent at this — it parses protocols deeply and logs anomalies.*

## 25.4 Network Timeline Analysis

### Steps:
1. Convert all timestamps to UTC.
2. Merge data sources chronologically (captures, firewall, IDS, DNS, proxy, endpoints).
3. Build event sequence:

```text
T+0:00  — Phishing email received
T+0:05  — User clicks link → HTTP GET to malicious URL
T+0:05  — Malware downloaded (HTTP 200 OK, Content-Type: application/octet-stream)
T+0:06  — DNS query for c2server.com
T+0:06  — TLS connection to c2server.com:443
T+0:06  — Beaconing begins (every 60 seconds)
T+2:30  — Lateral movement: SMB connection to fileserver
T+2:35  — Large data transfer to c2server.com
T+3:00  — Additional malware dropped on fileserver
```

## 25.5 Traffic Decryption Techniques

1. **Pre-Master Secret Logs (SSLKEYLOGFILE)**:
   - Works with Chrome, Firefox, curl, etc. Set env variable before capturing.
2. **RSA Private Key**:
   - Only for RSA key exchange (no forward secrecy). Increasingly rare.
3. **Kerberos Keytab**:
   - Decrypt Kerberos traffic in Wireshark (`Edit` → `Preferences` → `Protocols` → `KRB5` → `Keytab file`).
4. **WPA/WPA2 Decryption**:
   - Need PSK + full 4-way handshake (`Edit` → `Preferences` → `Protocols` → `IEEE 802.11` → `Decryption keys`).
5. **IPsec Decryption**:
   - Need SAs (Security Associations) and keys. ESP decryption in Wireshark preferences.
6. **Proxy/MITM Decryption**:
   - SSL inspection appliance. Captures decrypted traffic.

---

# PART 26: PROFESSIONAL TERMINOLOGY & FRAMEWORKS

## 26.1 SOC-Specific Network Terms

- **NDR**: Network Detection and Response (e.g. Darktrace, ExtraHop, Vectra, Corelight).
- **NTA**: Network Traffic Analysis (predecessor term to NDR).
- **NSM**: Network Security Monitoring.
- **PCAP**: Packet Capture.
- **BPF**: Berkeley Packet Filter.
- **DPI**: Deep Packet Inspection.
- **TAP**: Test Access Point (hardware).
- **SPAN**: Switched Port Analyzer (port mirroring).
- **RSPAN/ERSPAN**: Remote SPAN / Encapsulated Remote SPAN.
- **NetFlow/IPFIX**: Flow metadata collection protocols.
- **sFlow**: Sampled flow (statistical sampling).
- **SOC**: Security Operations Center.
- **SIEM**: Security Information and Event Management.
- **SOAR**: Security Orchestration, Automation, and Response.
- **TI**: Threat Intelligence.
- **IoC**: Indicator of Compromise.
- **IoA**: Indicator of Attack (behavioral).
- **TTP**: Tactics, Techniques, and Procedures (most valuable intelligence).
- **APT**: Advanced Persistent Threat.
- **C2/C&C**: Command and Control.
- **DGA**: Domain Generation Algorithm.
- **Fast Flux**: Rapid IP rotation for domains.
- **Beaconing**: Periodic C2 check-in behavior.
- **Pivot**: Using one compromised system to access others.
- **Kill Chain**: Lockheed Martin Cyber Kill Chain (Recon → Weaponization → Delivery → Exploit → Install → C2 → Actions).
- **Diamond Model**: Adversary ↔ Capability ↔ Infrastructure ↔ Victim.
- **MITRE ATT&CK**: Framework of adversary TTPs organized by tactic.

## 26.2 MITRE ATT&CK Network-Relevant Techniques

- **Initial Access**:
  - `T1566` — Phishing (network: email protocols, HTTP downloads)
  - `T1133` — External Remote Services (VPN, RDP, SSH from external)
  - `T1190` — Exploit Public-Facing Application (web exploits)
- **Execution**:
  - `T1059` — Command and Scripting Interpreter (PowerShell over WinRM)
- **Discovery**:
  - `T1046` — Network Service Discovery (port scanning)
  - `T1018` — Remote System Discovery (ping sweep, DNS queries)
  - `T1049` — System Network Connections Discovery
- **Lateral Movement**:
  - `T1021` — Remote Services (RDP, SSH, SMB, WinRM)
  - `T1570` — Lateral Tool Transfer (file copy over SMB)
  - `T1550` — Use Alternate Authentication Material (PtH, PtT)
- **Command and Control**:
  - `T1071` — Application Layer Protocol (HTTP, DNS, SMTP for C2)
  - `T1573` — Encrypted Channel (HTTPS, custom encryption)
  - `T1572` — Protocol Tunneling (DNS tunneling, ICMP tunneling)
  - `T1571` — Non-Standard Port (C2 on unusual ports)
  - `T1568` — Dynamic Resolution (DGA, fast flux)
  - `T1105` — Ingress Tool Transfer (downloading tools)
  - `T1090` — Proxy (multi-hop proxy, domain fronting)
  - `T1001` — Data Obfuscation (junk data, steganography)
  - `T1132` — Data Encoding (base64, XOR in C2)
- **Exfiltration**:
  - `T1041` — Exfiltration Over C2 Channel
  - `T1048` — Exfiltration Over Alternative Protocol
  - `T1567` — Exfiltration Over Web Service (cloud storage)
  - `T1020` — Automated Exfiltration
  - `T1030` — Data Transfer Size Limits (chunked exfil to avoid detection)
- **Collection**:
  - `T1039` — Data from Network Shared Drive

## 26.3 Key Port Numbers SOC Analysts Must Know

| Port | Protocol | Service | SOC Notes |
| :--- | :--- | :--- | :--- |
| **20** | TCP | FTP Data | Active FTP data channel |
| **21** | TCP | FTP Control | Cleartext credentials |
| **22** | TCP | SSH/SFTP/SCP | Brute force target, tunneling |
| **23** | TCP | Telnet | Cleartext, should be disabled |
| **25** | TCP | SMTP | Email relay, spam |
| **53** | TCP/UDP | DNS | Tunneling, amplification |
| **67/68** | UDP | DHCP | Rogue DHCP |
| **69** | UDP | TFTP | No auth, sometimes used by malware |
| **80** | TCP | HTTP | Web traffic, C2 |
| **88** | TCP/UDP | Kerberos | AS-REQ/TGS-REQ, Kerberoasting |
| **110** | TCP | POP3 | Cleartext email |
| **111** | TCP/UDP | RPCbind/Portmapper | RPC enumeration |
| **123** | UDP | NTP | Amplification attacks |
| **135** | TCP | MS RPC Endpoint Mapper | Lateral movement (WMI, DCOM) |
| **137-139** | TCP/UDP | NetBIOS | Legacy Windows, LLMNR poisoning |
| **143** | TCP | IMAP | Cleartext email |
| **161/162** | UDP | SNMP | Community string attacks, enum |
| **389** | TCP/UDP | LDAP | Directory queries, CLDAP amplification |
| **443** | TCP | HTTPS | Encrypted web, C2, tunneling |
| **445** | TCP | SMB/CIFS | Lateral movement, EternalBlue |
| **465** | TCP | SMTPS | Encrypted email submission |
| **514** | UDP | Syslog | Log collection |
| **587** | TCP | SMTP Submission | Email with auth |
| **636** | TCP | LDAPS | Encrypted LDAP |
| **993** | TCP | IMAPS | Encrypted IMAP |
| **995** | TCP | POP3S | Encrypted POP3 |
| **1080** | TCP | SOCKS Proxy | Proxy, tunneling |
| **1433** | TCP | MS SQL | Database, SQL injection |
| **1521** | TCP | Oracle DB | Database |
| **2049** | TCP/UDP | NFS | Network file system |
| **3306** | TCP | MySQL | Database |
| **3389** | TCP | RDP | Remote desktop, brute force |
| **4444** | TCP | Metasploit Default | Reverse shell (very suspicious) |
| **5432** | TCP | PostgreSQL | Database |
| **5900-5901** | TCP | VNC | Remote access |
| **5985** | TCP | WinRM HTTP | PowerShell remoting |
| **5986** | TCP | WinRM HTTPS | PowerShell remoting (encrypted) |
| **6379** | TCP | Redis | In-memory DB, often exposed |
| **8080** | TCP | HTTP Proxy/Alt | Web proxy, alternate HTTP |
| **8443** | TCP | HTTPS Alt | Alternate HTTPS |
| **8888** | TCP | Various | HTTP alt, Jupyter |
| **9200** | TCP | Elasticsearch | Often misconfigured/exposed |
| **27017** | TCP | MongoDB | NoSQL, often exposed |

---

# PART 27: PRACTICAL PLAYBOOKS & SOPs

## 27.1 Playbook: Investigating a Suspicious Outbound Connection

**TRIGGER**: Alert for outbound connection to known-bad IP or suspicious behavior

- [ ] **Step 1: Gather Initial Information**
  - [ ] What is the source IP (internal host)?
  - [ ] What is the destination IP/domain?
  - [ ] What port/protocol?
  - [ ] When did it start? Is it ongoing?
  - [ ] What triggered the alert (IDS, TI match, anomaly)?
- [ ] **Step 2: Enrich Destination**
  - [ ] Check threat intelligence (VirusTotal, AbuseIPDB, OTX)
  - [ ] Check domain age and registration (WHOIS)
  - [ ] Check passive DNS history
  - [ ] Check certificate (if HTTPS)
  - [ ] Check GeoIP location
  - [ ] Check JARM fingerprint
  - [ ] Check if destination is a known cloud/CDN or hosting provider
- [ ] **Step 3: Analyze Traffic Pattern**
  - [ ] Pull NetFlow data for the source IP
  - [ ] Is this a one-time connection or recurring (beaconing)?
  - [ ] How much data was transferred? (upload vs. download ratio)
  - [ ] What was the session duration?
  - [ ] Were there DNS queries preceding the connection?
  - [ ] What other external IPs has this host connected to?
- [ ] **Step 4: Examine Host**
  - [ ] What is the hostname / user associated with this IP? (DHCP/AD)
  - [ ] Check endpoint logs (Sysmon, EDR)
  - [ ] What process initiated the connection?
  - [ ] Are there any other indicators of compromise on the host?
- [ ] **Step 5: Check PCAP (if available)**
  - [ ] Examine packet payload
  - [ ] Check TLS certificate, JA3 hash
  - [ ] Look for known C2 patterns
  - [ ] Extract any transferred files
- [ ] **Step 6: Determine Verdict**
  - [ ] True Positive (malicious) → Escalate to Incident Response
  - [ ] Benign True Positive (alert is correct, behavior is legitimate)
  - [ ] False Positive → Tune detection rule
  - [ ] Suspicious/Inconclusive → Continue monitoring, add to watchlist
- [ ] **Step 7: Document & Report**
  - [ ] Record findings in case management
  - [ ] Update IoCs if new ones discovered
  - [ ] Adjust detection rules as needed

## 27.2 Playbook: Investigating Potential Data Exfiltration

**TRIGGER**: Alert for unusual outbound data volume or transfers to suspicious destinations

- [ ] **Step 1: Confirm the Alert**
  - [ ] Verify the data volume (NetFlow/proxy logs)
  - [ ] Identify source and destination
  - [ ] Determine the protocol/application used
  - [ ] Check if this is a known legitimate transfer (backups, updates, etc.)
- [ ] **Step 2: Assess the Destination**
  - [ ] Is it a known file sharing service (Dropbox, OneDrive, etc.)?
  - [ ] Is it a personal email service?
  - [ ] Is it a known-bad IP/domain?
  - [ ] Is it geographically unusual?
- [ ] **Step 3: Investigate the Source**
  - [ ] Who is the user? What is their role?
  - [ ] What data do they have access to?
  - [ ] Is this behavior consistent with their normal activity?
  - [ ] Check DLP alerts for this user
  - [ ] Check recent file access patterns
- [ ] **Step 4: Analyze the Data Transfer**
  - [ ] What type of data was transferred?
  - [ ] Were files compressed/encrypted before transfer?
  - [ ] What was the exact volume and duration?
  - [ ] Was it a continuous stream or chunked transfer?
- [ ] **Step 5: Correlate**
  - [ ] Any prior security alerts for this user/host?
  - [ ] Any recent access to sensitive file shares?
  - [ ] Any recent privilege escalation or unusual authentication?
  - [ ] HR context (notice period, performance issues)?
- [ ] **Step 6: Containment (if confirmed)**
  - [ ] Block outbound connection
  - [ ] Isolate host from network
  - [ ] Preserve evidence (memory dump, disk image, PCAP)
  - [ ] Disable user account
  - [ ] Notify management/legal/HR as appropriate
- [ ] **Step 7: Forensics**
  - [ ] What exactly was exfiltrated?
  - [ ] How was access obtained?
  - [ ] Timeline of all actions
  - [ ] Full scope assessment

## 27.3 Playbook: Investigating DNS Tunneling

**TRIGGER**: IDS alert, anomaly detection, or TI match for DNS tunneling

- [ ] **Step 1: Identify the Indicators**
  - [ ] Which internal host is generating the queries?
  - [ ] What domain is being queried?
  - [ ] What are the query types (A, TXT, CNAME, NULL)?
  - [ ] What is the volume and frequency?
- [ ] **Step 2: Analyze DNS Queries**
  - [ ] Examine subdomain labels:
    - [ ] Length > 30 characters?
    - [ ] High entropy (random characters)?
    - [ ] Base32/Base64 encoding patterns?
  - [ ] Examine responses:
    - [ ] TXT records with large/encoded data?
    - [ ] Multiple A records?
    - [ ] CNAME chains?
  - [ ] Calculate query statistics:
    - [ ] Queries per minute to the domain
    - [ ] Total unique subdomains queried
    - [ ] Total bytes in subdomain labels
- [ ] **Step 3: Investigate the Domain**
  - [ ] WHOIS information
  - [ ] Registration date (newly registered = suspicious)
  - [ ] NS records (who controls this domain's DNS?)
  - [ ] Reputation in threat intelligence
- [ ] **Step 4: Investigate the Host**
  - [ ] What process is generating DNS queries?
  - [ ] Recent software installations?
  - [ ] Malware scan results?
  - [ ] EDR telemetry?
- [ ] **Step 5: Containment**
  - [ ] Block the domain at DNS resolver
  - [ ] Block at proxy/firewall
  - [ ] Isolate the compromised host
  - [ ] Check other hosts for same domain queries
- [ ] **Step 6: Eradication & Recovery**
  - [ ] Remove malware
  - [ ] Re-image host if needed
  - [ ] Reset credentials
  - [ ] Conduct scope assessment (what was accessed/exfiltrated?)

## 27.4 Quick Reference: Wireshark Analysis Checklist

When handed a PCAP file for investigation:

- [ ] **1. File info**: `capinfos file.pcap` (capture duration, packets, size)
- [ ] **2. Protocol Hierarchy**: What protocols are present? (Statistics → Protocol Hierarchy)
- [ ] **3. Conversations**: Who is talking to whom? (Statistics → Conversations). Sort by bytes to find large transfers.
- [ ] **4. Endpoints**: What hosts are active? (Statistics → Endpoints). Check for unexpected external IPs.
- [ ] **5. DNS analysis**: What domains were queried? Filter: `dns`. Check for unusual domains, DGA, tunneling indicators.
- [ ] **6. HTTP analysis**: What web requests were made? Filter: `http`. Check User-Agents, URIs, response codes. Export objects: File → Export Objects → HTTP.
- [ ] **7. TLS analysis**: What encrypted connections were made? Filter: `tls.handshake.type == 1` (Client Hellos). Check SNI values, certificate details.
- [ ] **8. Anomalies**: Expert Information (Analyze → Expert Information). Check for errors, warnings.
- [ ] **9. Suspicious patterns**:
  - [ ] Beaconing (regular intervals)
  - [ ] Large uploads
  - [ ] Unusual ports
  - [ ] Direct IP access (no DNS)
  - [ ] Known-bad indicators
- [ ] **10. Follow streams of interest**: Right-click → Follow → TCP/HTTP/TLS Stream. Examine conversation content.
- [ ] **11. Extract and analyze files**: Export objects or use NetworkMiner. Hash and check VirusTotal.
- [ ] **12. Document findings**: Timeline of events, IoCs discovered, recommendations.

---

# APPENDIX A: COMMON WIRESHARK DISPLAY FILTER CHEAT SHEET

### General
```wireshark
frame.number == 100
frame.len > 1000
frame.time >= "2024-01-01"
```

### Ethernet
```wireshark
eth.addr == aa:bb:cc:dd:ee:ff
eth.src == aa:bb:cc:dd:ee:ff
eth.type == 0x0800
```

### IP
```wireshark
ip.addr == 192.168.1.1
ip.src == 10.0.0.0/8
ip.dst == 8.8.8.8
ip.ttl < 10
ip.proto == 6
ip.flags.mf == 1          # More fragments
ip.frag_offset > 0        # Fragment offset
```

### TCP
```wireshark
tcp.port == 80
tcp.dstport == 443
tcp.srcport == 4444
tcp.flags.syn == 1
tcp.flags.ack == 1
tcp.flags.reset == 1
tcp.flags.fin == 1
tcp.flags == 0x002         # SYN only
tcp.flags == 0x012         # SYN-ACK
tcp.flags == 0x010         # ACK only
tcp.flags == 0x029         # FIN-PSH-URG (XMAS)
tcp.flags == 0x000         # NULL scan
tcp.stream eq 5
tcp.analysis.retransmission
tcp.analysis.duplicate_ack
tcp.analysis.zero_window
tcp.window_size == 0
tcp.len > 0                # TCP with payload
```

### UDP
```wireshark
udp.port == 53
udp.dstport == 161
udp.length > 512
```

### DNS
```wireshark
dns
dns.qry.name == "example.com"
dns.qry.name contains "evil"
dns.qry.type == 1          # A
dns.qry.type == 28         # AAAA
dns.qry.type == 16         # TXT
dns.qry.type == 15         # MX
dns.qry.type == 255        # ANY
dns.flags.rcode == 3       # NXDOMAIN
dns.flags.rcode == 0       # NOERROR
dns.flags.response == 1    # Responses only
dns.flags.response == 0    # Queries only
dns.resp.len > 100
```

### HTTP
```wireshark
http
http.request
http.response
http.request.method == "GET"
http.request.method == "POST"
http.request.uri contains "/admin"
http.host contains "evil"
http.user_agent contains "python"
http.response.code == 200
http.response.code == 404
http.response.code >= 400
http.content_type contains "executable"
http.content_length > 1000000
http.cookie contains "session"
http.request.full_uri contains "base64"
http.file_data contains "MZ"     # PE file in response
```

### TLS/SSL
```wireshark
tls
tls.handshake
tls.handshake.type == 1    # Client Hello
tls.handshake.type == 2    # Server Hello
tls.handshake.type == 11   # Certificate
tls.handshake.extensions.server_name contains "evil"
tls.record.version == 0x0301   # TLS 1.0
tls.record.version == 0x0303   # TLS 1.2
ssl.alert_message
```

### SMB
```wireshark
smb || smb2
smb2.cmd == 5              # Create (file open)
smb2.filename contains ".exe"
smb2.tree contains "ADMIN$"
smb2.tree contains "C$"
smb2.tree contains "IPC$"
```

### Kerberos
```wireshark
kerberos
kerberos.msg_type == 10    # AS-REQ
kerberos.msg_type == 11    # AS-REP
kerberos.msg_type == 12    # TGS-REQ
kerberos.msg_type == 13    # TGS-REP
kerberos.msg_type == 30    # KRB-ERROR
kerberos.error_code == 6   # CLIENT_NOT_FOUND
kerberos.error_code == 24  # PREAUTH_FAILED
```

### ICMP
```wireshark
icmp
icmp.type == 8             # Echo request
icmp.type == 0             # Echo reply
icmp.type == 3             # Destination unreachable
icmp.type == 11            # Time exceeded
icmp.data.len > 64         # Large ICMP payload (tunneling?)
```

### ARP
```wireshark
arp
arp.opcode == 1            # Request
arp.opcode == 2            # Reply
arp.duplicate-address-detected
```

### DHCP
```wireshark
dhcp
dhcp.type == 1             # Discover
dhcp.type == 2             # Offer
dhcp.type == 3             # Request
dhcp.type == 5             # ACK
```

### Logical Operators
```wireshark
&&   (and)
||   (or)
!    (not)
==   (equals)
!=   (not equal)
>    (greater than)
<    (less than)
>=   (greater than or equal)
<=   (less than or equal)
contains
matches (regex)
in {value1 value2 value3}
```

---

# APPENDIX B: ZEEK LOG FILES REFERENCE

### Network Logs
- **conn.log**: Every connection (TCP/UDP/ICMP): IPs, ports, bytes, duration, state.
- **dns.log**: DNS queries and responses.
- **http.log**: HTTP requests: method, URI, user-agent, status code, MIME type.
- **ssl.log**: TLS handshake details: version, cipher, certificate, SNI, JA3/JA3S.
- **smtp.log**: SMTP transactions.
- **ftp.log**: FTP sessions.
- **ssh.log**: SSH connections: version, auth attempts, direction.
- **dhcp.log**: DHCP transactions.
- **ntp.log**: NTP activity.
- **tunnel.log**: Tunneled connections detected.
- **sip.log**: SIP (VoIP) activity.
- **rdp.log**: RDP connections.
- **smb_mapping.log**: SMB tree connects (share access).
- **smb_files.log**: SMB file access.
- **dce_rpc.log**: DCE/RPC calls.
- **kerberos.log**: Kerberos authentication.
- **ntlm.log**: NTLM authentication.
- **radius.log**: RADIUS authentication.
- **socks.log**: SOCKS proxy connections.
- **modbus.log**: Modbus (ICS/SCADA).