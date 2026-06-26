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
- ✦ Received header chain 
