- [PART 8: WIRESHARK MASTERY](#part-8-wireshark-mastery)
  - [8.1 Display Filters vs Capture Filters](#81-display-filters-vs-capture-filters)
  - [8.2 Essential Display Filters](#82-essential-display-filters)
  - [8.3 Wireshark Features for SOC](#83-wireshark-features-for-soc)
  - [8.4 Wireshark Columns Configuration for SOC](#84-wireshark-columns-configuration-for-soc)
 
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
