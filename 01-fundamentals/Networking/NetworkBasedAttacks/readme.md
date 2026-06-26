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
