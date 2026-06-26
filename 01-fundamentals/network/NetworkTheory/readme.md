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