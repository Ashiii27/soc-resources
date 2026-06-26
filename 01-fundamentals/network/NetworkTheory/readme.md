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
  - 
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


consistency

---
