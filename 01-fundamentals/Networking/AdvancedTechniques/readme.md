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