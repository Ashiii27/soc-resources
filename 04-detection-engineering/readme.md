<div align="center">

# ⚙️ 04 - Detection Engineering
**Don't wait for alerts to find you. Build the logic that finds them first.**

[![Difficulty](https://img.shields.io/badge/Difficulty-Advanced-red?style=flat-square)](https://github.com/Ashiii27/soc-resources)
[![Role](https://img.shields.io/badge/Role-Detection%20Engineer%20%7C%20L3-blue?style=flat-square)](https://github.com/Ashiii27/soc-resources)
[![Status](https://img.shields.io/badge/Status-In%20Progress-yellow?style=flat-square)](https://github.com/Ashiii27/soc-resources)

</div>

---

## 🎯 Module Objective
Detection Engineering is the discipline of **systematically building, testing, and maintaining detection logic** that identifies adversarial behaviour in your environment. This module covers the full detection-as-code lifecycle — from threat modelling to rule deployment and tuning.

---

## 🗺️ The Detection Engineering Roadmap

### 1. 🧩 The Detection Engineering Lifecycle
*Detection is a product, not a one-time task.*
- [ ] **Threat Modelling**: What are the most likely attacks against our environment? (Use MITRE ATT&CK + threat intel).
- [ ] **Hypothesis Formation**: "APT29 uses WMI for lateral movement — do we have detection for T1047?"
- [ ] **Data Source Identification**: What logs do we need? Are they available? Are they normalized?
- [ ] **Rule Authoring**: Write the detection in Sigma, SPL, KQL, or YARA.
- [ ] **Testing**: Validate against attack simulations (Atomic Red Team, Caldera).
- [ ] **Deployment & Monitoring**: Deploy to SIEM, monitor false positive rate, tune accordingly.
- [ ] **Maintenance**: Update rules as the threat landscape evolves.

### 2. 📝 Sigma Rules
*The vendor-agnostic detection rule format.*
- [ ] **Structure**: `title`, `status`, `description`, `logsource`, `detection`, `condition`, `falsepositives`, `level`, `tags`.
- [ ] **Log Sources**: Defining `category`, `product`, `service` for log source targeting.
- [ ] **Detection Logic**: `keywords`, `selection`, `filter`, `condition` using AND/OR/NOT logic.
- [ ] **Converting Sigma**: Using `sigma-cli` to convert rules to SPL, KQL, Lucene, etc.
- [ ] **Sigma Rule Example**:
  ```yaml
  title: Suspicious PowerShell Encoded Command
  status: stable
  logsource:
      category: process_creation
      product: windows
  detection:
      selection:
          CommandLine|contains:
              - '-enc '
              - '-EncodedCommand'
      filter:
          ParentImage|endswith: '\wsmprovhost.exe'
      condition: selection and not filter
  falsepositives:
      - Legitimate administrative scripts
  level: medium
  tags:
      - attack.execution
      - attack.t1059.001
  ```

### 3. 🔍 YARA Rules
*Pattern matching for malware and file-based threats.*
- [ ] **Structure**: `rule` name, `meta`, `strings`, `condition`.
- [ ] **String Types**: Text strings, hex patterns, regex patterns.
- [ ] **Conditions**: Boolean logic combining string matches, file size, PE header checks.
- [ ] **PE Module**: Inspecting imports, exports, sections, and file metadata.
- [ ] **YARA Rule Example**:
  ```yara
  rule Suspicious_PowerShell_Download {
      meta:
          description = "Detects PowerShell downloading from the internet"
          author = "Ash"
          severity = "high"
      strings:
          $ps1 = "IEX" ascii nocase
          $ps2 = "DownloadString" ascii nocase
          $ps3 = "WebClient" ascii nocase
      condition:
          any of ($ps*)
  }
  ```

### 4. 🏗️ Detection-as-Code (DaC)
*Treating detection rules like software.*
- [ ] **Version Control**: Storing all detection rules in Git for change tracking.
- [ ] **CI/CD Pipelines**: Automatically testing and deploying rules on merge.
- [ ] **Unit Testing**: Validating rules against synthetic log data before deployment.
- [ ] **Rule Coverage Metrics**: Tracking ATT&CK technique coverage across your rule library.
- [ ] **Documentation**: Every rule should have context — what it detects, why, and known false positives.

### 5. 🧪 Testing & Validation
*A rule that hasn't been tested is a rule you don't trust.*
- [ ] **Atomic Red Team**: Execute individual ATT&CK technique simulations to validate detection coverage.
- [ ] **MITRE Caldera**: Automated adversary emulation platform.
- [ ] **Purple Team Exercises**: Red team runs TTPs while blue team validates detections in real time.
- [ ] **Replay Testing**: Replaying captured attack traffic/logs against new rules.

### 6. 📉 False Positive Management
*A noisy detection is an ignored detection.*
- [ ] **Baselining**: Understanding what "normal" looks like before alerting on anomalies.
- [ ] **Allowlisting**: Excluding known-good entities without creating blind spots.
- [ ] **Risk Scoring**: Using entity risk scores (user, host) to contextualize alerts.
- [ ] **Feedback Loop**: Closing the loop — L1 FP decisions should inform rule tuning.

---

## 📊 Detection Coverage Matrix

| ATT&CK Tactic | Key Techniques | Detection Approach |
| :--- | :--- | :--- |
| **Initial Access** | T1566 Phishing | Email gateway logs, attachment analysis |
| **Execution** | T1059 PowerShell/cmd | Process creation logs (4688), Sysmon EID 1 |
| **Persistence** | T1053 Scheduled Tasks | Event 4698, registry Run keys |
| **Privilege Escalation** | T1548 UAC Bypass | Process parent-child anomalies |
| **Defence Evasion** | T1027 Obfuscation | Encoded command detection, entropy analysis |
| **Credential Access** | T1003 LSASS Dump | Sysmon EID 10, process access to lsass.exe |
| **Lateral Movement** | T1021 Remote Services | Logon type 3, WMI, PsExec detection |
| **Exfiltration** | T1041 C2 Channel | DNS beacon detection, large outbound transfers |

---

## 🚀 Quick Start Learning Path

| Topic | Recommended Resource | Type |
| :--- | :--- | :--- |
| **Sigma Rules** | [Sigma HQ on GitHub](https://github.com/SigmaHQ/sigma) | Open Rule Library |
| **YARA** | [YARA Documentation](https://yara.readthedocs.io) | Official Docs |
| **Atomic Red Team** | [Red Canary Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Testing Framework |
| **Detection Maturity** | [Detection Maturity Level (DML)](http://ryanstillions.blogspot.com/2014/04/the-dml-model_21.html) | Blog |

---

## 🛠️ Detection Engineering Toolkit

- **Sigma CLI**: Convert Sigma rules to any SIEM query language.
- **YARA**: Pattern matching engine for file and memory scanning.
- **Uncoder.io**: Online Sigma rule converter and IDE.
- **Atomic Red Team**: ATT&CK-aligned test library for validating detections.
- **MITRE ATT&CK Navigator**: Visual coverage mapping for your rule library.

---

> **💡 Analyst's Insight: Quality Over Quantity**
> A detection library of 50 high-fidelity, well-tuned rules is worth more than 5,000 noisy ones. Alert fatigue is the #1 reason SOC analysts miss real incidents. Build rules that fire accurately and fire for a reason.

---

<div align="center">

**Previous:** $\leftarrow$ [03 - SIEM & Logging](./../03-siem-and-logging/) &nbsp;&nbsp; | &nbsp;&nbsp; **Next:** $\rightarrow$ [05 - Incident Response](./../05-incident-response/)

</div>
