# Phishing Email Analysis & Incident Response Lab

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Category](https://img.shields.io/badge/Category-SOC%20Investigation-red.svg)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange.svg)
![OS](https://img.shields.io/badge/Environment-Kali%20Linux-dragon.svg)

---

## Executive Summary

This project documents a comprehensive, end-to-end technical investigation of an authentic phishing email sample (`sample1.eml`). The analysis spans header inspection, Mail Transfer Agent (MTA) origin tracing, payload and tracking parameter extraction, threat intelligence correlation, and attack mapping to the **MITRE ATT&CK** enterprise framework.

### **Incident Overview**
* **Incident Type:** Suspicious Email / Malicious Hyperlink Campaign
* **Severity Level:** Medium / High
* **Primary Lure:** Financial / Rewards Incentive (`Copa 2026: Oportunidade de ... no valor de R$ 100.000,00`)
* **Impersonated Brand:** Visa (`nao-responder-Visa70103570@promocoes70103570`)
* **Key Findings:** 
  * Spoofed `From` display header with complete email authentication failure (SPF, DKIM, DMARC all `none`).
  * Automated phishing bulk mailer signature (`X-Mailer: Custom Mailer v1.0`).
  * Originating MTA IP (`95.179.194.86`) hosted on commercial VPS infrastructure (Vultr / The Constant Company, LLC).
  * Payload hosted on serverless infrastructure (`Google Cloud Run`) to bypass web reputation filters.
  * Active target-tracking URL parameter (`?cid=phishing@pot@hotmail.com`).

---

## Tools & Technologies Used

| Category | Tool / Service | Purpose |
| :--- | :--- | :--- |
| **OS / Environment** | Kali Linux VM | Isolated technical analysis environment |
| **CLI Utilities** | `grep`, `cat`, `sed`, `strings` | Command-line header parsing and link extraction |
| **Threat Intelligence** | VirusTotal | Originating IP reputation and ASN lookup |
| **Web Analysis** | URLScan.io | Safe headless sandbox scanning & TLS inspection |
| **Frameworks** | MITRE ATT&CK | Mapping adversary tactics and techniques |

---

## Incident Response & Technical Analysis Workflow

### **Phase 1: Detection & Initial Triage**
The raw email sample (`sample1.eml`) was ingested within an isolated Kali Linux analysis workspace. Initial inspection confirmed unauthenticated transmission pretending to originate from Visa promotional operations.

* **Sample Source:** [rf-peixoto/phishing_pot (GitHub)](https://github.com/rf-peixoto/phishing_pot/blob/main/email/sample-100.eml)

---

### **Phase 2: Header Parsing & Origin Tracing**

Using CLI regex utilities in Kali Linux, key anchor headers were extracted to reconstruct the hop-by-hop transmission pathway:

```bash
# Terminal command used to extract key anchor headers
grep -iE '^(From:|Return-Path:|Authentication-Results:|Reply-To:|Subject:|X-Mailer:)' sample1.eml
```

#### **Extracted Header Telemetry**
* **From Header:** `Visa <nao-responder-Visa70103570@promocoes70103570>`
* **Return-Path:** `nao-responder-Visa70103570@promocoes70103570`
* **Reply-To Address:** `suporte@notificacoes`
* **X-Mailer Tag:** `Custom Mailer v1.0` *(Confirms mass-automated script usage)*
* **Authentication Alignment:** `spf=none`, `dkim=none (message not signed)`, `dmarc=none`

#### **Originating MTA Tracing**
Following the bottom-up `Received:` header parsing rule, the first untrusted external server handoff was isolated:

```text
Received: from [127.0.0.1] (95.179.194.86) by BL6PEPF0001AB74.mail.protection.outlook.com...
```
* **True Originating IP:** `95.179.194.86`
* **ISP / Host:** The Constant Company, LLC (Vultr VPS - AS20473)

---

### **Phase 3: Payload & Link Extraction**

To safely extract embedded hyperlinks without manual browser exposure, line-buffered grep parameters were executed against the encoded message body:

```bash
# Extracting quoted-printable encoded hyperlinks
grep -iA 2 'href=3D"https' sample1.eml
```

#### **Quoted-Printable Decoding (`=3D`)**
* **Raw Extracted Payload:**
  `https://cop4asojateosom0-1094100152898.us-central1.run.app/?cid=3Dphishing@pot@hotmail.com`
* **Defanged Indicator (For Documentation):**
  `hxxps://cop4asojateosom0-1094100152898[.]us-central1[.]run[.]app/?cid=phishing@pot@hotmail[.]com`

#### **Phishing Kit Artifact**
The extraction revealed an unstripped template developer comment left behind by the adversary:
```html
<!-- Substitua o href="SITE" pelo link real -->
```
*(Translation: "Replace href="SITE" with the real link")*

---

### **Phase 4: Threat Intelligence Correlation**

#### **1. VirusTotal IP Reputation Check (`95.179.194.86`)**
* **Detection Score:** `0 / 92` (Clean / Unflagged baseline score)
* **SOC Analysis:** Newly provisioned or recycled cloud hosting IPs frequently return clean scores due to a lack of historical reports. Threat actors intentionally utilize transient cloud VPS providers (Vultr) to launch short-lived campaigns before perimeter blocklists update.
* **Passive DNS History:** Historical resolutions include utility domains (`securing-mail.com`, `mailbox.stpettersen.xyz`), confirming frequent IP reassignment.

#### **2. URLScan.io Sandbox Scan**
* **Target Domain:** `cop4asojateosom0-1094100152898.us-central1.run.app`
* **Destination IP:** `34.143.75.2` (Google Cloud Platform - AS396982)
* **TLS Certificate:** Issued by WR2 (Google Trust Services - 3-month short-lived cert)
* **HTTP Response:** `404 Page Not Found`
* **SOC Analysis:** Threat actors host temporary container instances on Google Cloud Run to acquire trusted SSL certificates and bypass reputation engines. Upon campaign completion (or bot detection), containers are terminated or return 404 responses.

---

## Complete Indicators of Compromise (IOCs)

| Indicator Type | Value / Pattern | Description / Context |
| :--- | :--- | :--- |
| **Sender IP** | `95.179.194.86` | Originating Vultr MTA Server IP |
| **Email Domain** | `promocoes70103570` | Spoofed Visa promotional domain |
| **Reply-To Address** | `suporte[@]notificacoes` | Fraudulent unmonitored reply target |
| **Malicious URL** | `hxxps://cop4asojateosom0-1094100152898[.]us-central1[.]run[.]app/?cid=phishing@pot@hotmail[.]com` | Defanged destination payload link |
| **Target Infrastructure**| `cop4asojateosom0-1094100152898.us-central1.run.app` | Google Cloud Run Serverless Instance |
| **Tracking Parameter** | `?cid=phishing@pot@hotmail.com` | Victim click-tracking identifier |

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Context / Operational Application |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1566.002` | Spearphishing Link | Adversary delivered phishing email with malicious hyperlink |
| **Credential Access** | `T1056.003` | Web Portal Capture | Destination link hosted fake portal to harvest user credentials |
| **Resource Development**| `T1584.004` | Compromise Infrastructure: Serverless | Abused Google Cloud Run container services to host payload |

---

## Containment & Remediation Recommendations

1. **Perimeter Controls:**
   * Ingest originating IP `95.179.194.86` and envelope domain `promocoes70103570` into boundary firewall and Secure Email Gateway (SEG) drop lists.
2. **Mailbox Remediation:**
   * Execute an enterprise-wide purge query across M365 / Google Workspace for all messages containing `X-Mailer: Custom Mailer v1.0` or matching sender patterns.
3. **Identity & Access Management:**
   * Force password resets and revoke active OAuth sessions for any users identified in target tracking parameters (`?cid=...`) who interacted with the link.
4. **Detection Engineering / SIEM Rule:**
   * Implement SIEM detection alerts flagging inbound emails originating from non-corporate MTAs that contain unauthenticated SPF/DKIM headers pointing to serverless container domains (`*.run.app`, `*.web.app`).

---

## SOC Reference Cheat Sheet: Header Analysis & `X-Mailer`

### **The 4 Key Anchor Headers**

| Header Tag | Search Focus | SOC Significance |
| :--- | :--- | :--- |
| `From:` | Display Name & Email | Identifies brand impersonation attempts. |
| `Return-Path:` | Envelope Sender | Identifies real bounce-back address and domain mismatches. |
| `Authentication-Results:` | `spf=`, `dkim=`, `dmarc=` | Verifies if sender IP is cryptographically authorized. |
| **Bottom** `Received:` | Bottom-most IP Address | Uncovers the true originating external MTA server. |

### **`X-Mailer` Fingerprint Guide**

* **What is `X-Mailer`?** An extended header identifying the application software or script used to compose and transmit an email.
* **Why Inspect It?** Threat actors use custom Python/PHP scripts to blast mass phishing emails. Detecting tags like `X-Mailer: Custom Mailer v1.0` or `PHPMailer` strongly signals automated tools rather than legitimate corporate users.

---

## Project Repository Structure

```text
├── README.md               # Incident Writeup & Technical Report
├── sample1.eml             # Raw Phishing Email Sample
├── docs/                   # Investigative Notes & IOC Lists
└── evidence/               # Screenshots of Header Analysis & Threat Intel
```

---
*Created by Krisha Nandakumar | Security Operations Center (SOC) Portfolio Project*
