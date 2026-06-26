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
