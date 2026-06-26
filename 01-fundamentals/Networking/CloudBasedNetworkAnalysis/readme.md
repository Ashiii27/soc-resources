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
