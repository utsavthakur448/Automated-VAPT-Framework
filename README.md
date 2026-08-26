# 🛡️ Automated VAPT Framework

> **A modular Python-based Vulnerability Assessment & Penetration Testing framework for authorized security testing and controlled laboratory environments.**

VULNSCOPE is a lightweight, modular **Vulnerability Assessment and Penetration Testing (VAPT)** framework written in Python.

It combines:

- 🔎 Network discovery
- 🌐 Web security assessment
- 🎯 Service/version-based vulnerability detection
- 🧩 CVE/CVSS correlation
- 📊 Risk prioritization
- 🧾 Evidence collection
- 📝 Structured logging
- 📄 PDF security reporting

into a single command-line assessment workflow.

> **Project Version:** `0.1.0`

---

## ⚠️ Legal & Ethical Use

VULNSCOPE is designed for:

- Authorized penetration testing
- Security research
- Cybersecurity education
- Controlled laboratory environments
- Systems owned by the tester

**Only scan systems that you own or have explicit permission to assess.**

Do not use this project to perform unauthorized vulnerability scanning, exploitation, or security testing against third-party systems.

The author is not responsible for misuse of this software.

---

# ✨ Features

## 🔎 Network Discovery

VULNSCOPE uses **Nmap** for network and service discovery.

Current capabilities include:

- Host discovery
- Open-port detection
- TCP service detection
- Service/version identification
- OS detection when provided by Nmap
- Hostname detection
- MAC address detection
- Vendor identification
- Nmap result parsing
- Rich terminal rendering

---

## 🎯 Network Vulnerability Assessment

The framework currently contains service/version-oriented checks for:

| Service / Technology |
|---|
| vsftpd |
| Apache HTTP Server |
| Samba |
| MySQL |
| UnrealIRCd |
| Apache Tomcat |

Findings can contain:

- Vulnerability title
- Severity
- CVE
- CVSS score
- Detection method
- Confidence level
- Priority
- Evidence
- Remediation
- Product
- Version
- CPE
- References

---

# 🌐 Web Security Assessment

VULNSCOPE includes lightweight web security checks designed for controlled security assessment.

### Current checks

- 🔐 Security header analysis
- 🔍 Information disclosure
- 📂 Directory listing detection
- 💉 SQL error / SQL injection indicators
- 🧪 Reflected XSS indicators
- 🔧 HTTP method analysis
- 📁 Sensitive path exposure
- 🍪 Authentication/session security indicators
- 🖥️ Server technology disclosure
- 🧬 Web technology fingerprinting

> Web findings that rely on reflection or error signatures are **indicators**, not automatic proof of exploitability. Manual validation is recommended.

---

# 📊 Risk Prioritization

VULNSCOPE combines severity and CVSS information to prioritize findings.

| Severity | Priority |
|---|---|
| 🔴 CRITICAL | IMMEDIATE |
| 🟠 HIGH | HIGH |
| 🟡 MEDIUM | MEDIUM |
| 🟢 LOW | LOW |
| 🔵 INFO | INFORMATIONAL |

The framework also calculates:

- Overall risk rating
- Overall risk score
- Severity distribution
- Individual finding risk scores
- Remediation priority

---

# 🧾 Evidence Collection

VULNSCOPE can collect evidence associated with security findings.

Evidence may include:

- Target
- URL
- HTTP status
- Response headers
- Response excerpt
- Detection method
- Confidence level
- Finding information

This helps make assessment results easier to review and validate.

---

# 📄 PDF Security Reporting

Each completed assessment can generate a structured PDF report.

The report can contain:

- Executive Summary
- Target Information
- Nmap Discovery
- Network Vulnerability Findings
- Web Security Findings
- CVE/CVSS information
- Risk Assessment
- Severity Distribution
- Evidence
- Remediation Recommendations
- Assessment Methodology
- Conclusion

Generated reports are stored under:

```text
reports/
```

> Generated reports and logs should normally remain local and should not be committed to a public repository if they contain sensitive target information.

---

# 📝 Logging

Assessment lifecycle events are written to:

```text
reports/vapt.log
```

Logging includes events such as:

- Target validation
- Scope validation
- Nmap discovery
- Vulnerability assessment
- Web assessment
- Risk assessment
- Assessment completion

---

# 🏗️ Architecture

```text
                   Automated VAPT Framework
                              │
                              ▼
                     ┌─────────────────┐
                     │   Target Input  │
                     └────────┬────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │ Target Validate │
                     └────────┬────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │ Scope Validate  │
                     └────────┬────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │ Nmap Discovery   │
                     └────────┬────────┘
                              │
                 ┌────────────┴────────────┐
                 ▼                         ▼
        ┌──────────────────┐      ┌──────────────────┐
        │ Network Security │      │ Web Security     │
        │ Assessment       │      │ Assessment       │
        └────────┬─────────┘      └────────┬─────────┘
                 │                         │
                 └────────────┬────────────┘
                              ▼
                     ┌─────────────────┐
                     │ Findings Engine │
                     └────────┬────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │ Risk Prioritize │
                     └────────┬────────┘
                              │
                 ┌────────────┴────────────┐
                 ▼                         ▼
        ┌──────────────────┐      ┌──────────────────┐
        │ Terminal Results │      │ PDF Security     │
        │                  │      │ Report           │
        └──────────────────┘      └──────────────────┘
```

---

# 📁 Project Structure

```text
Automated-VAPT-Framework/
│
├── config/
│   └── default.json
│
├── core/
│   ├── asset.py
│   ├── engine.py
│   ├── logger.py
│   ├── scan_result.py
│   ├── scope.py
│   └── target.py
│
├── modules/
│   │
│   ├── discovery/
│   │   ├── nmap_scanner.py
│   │   ├── parser.py
│   │   └── renderer.py
│   │
│   ├── evidence/
│   │   └── collector.py
│   │
│   ├── reporting/
│   │   └── pdf_report.py
│   │
│   ├── risk/
│   │   ├── cvss.py
│   │   ├── prioritizer.py
│   │   └── severity.py
│   │
│   ├── vulnerabilities/
│   │   ├── checks/
│   │   ├── database.py
│   │   ├── engine.py
│   │   ├── models.py
│   │   ├── renderer.py
│   │   ├── version.py
│   │   └── risk/
│   │
│   └── web/
│       ├── checks/
│       ├── engine.py
│       ├── fingerprint.py
│       ├── headers.py
│       ├── models.py
│       └── scanner.py
│
├── reports/
│   └── .gitkeep
│
├── requirements.txt
├── README.md
└── vapt.py
```

---

# 🔄 Assessment Workflow

```text
                 ┌───────────────────┐
                 │    Target Input   │
                 └─────────┬─────────┘
                           │
                           ▼
                 ┌───────────────────┐
                 │ Target Validation │
                 └─────────┬─────────┘
                           │
                           ▼
                 ┌───────────────────┐
                 │ Scope Validation  │
                 └─────────┬─────────┘
                           │
                           ▼
                 ┌───────────────────┐
                 │  Nmap Discovery   │
                 └─────────┬─────────┘
                           │
                 ┌─────────┴─────────┐
                 ▼                   ▼
       ┌───────────────────┐ ┌───────────────────┐
       │ Network Assessment│ │ Web Assessment    │
       └─────────┬─────────┘ └─────────┬─────────┘
                 │                     │
                 └──────────┬──────────┘
                            ▼
                  ┌──────────────────┐
                  │ Findings Combined│
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Risk Prioritizer │
                  └────────┬─────────┘
                           │
                  ┌────────┴────────┐
                  ▼                 ▼
          ┌──────────────┐  ┌──────────────┐
          │ CLI Results  │  │ PDF Report   │
          └──────────────┘  └──────────────┘
```

---

# 🚀 Installation

## 1. Clone the repository

```bash
git clone https://github.com/hariomsingh045/NEXUS-VAPT.git
cd NEXUS-VAPT
```

## 2. Create a virtual environment

```bash
python3 -m venv venv
```

## 3. Activate the environment

```bash
source venv/bin/activate
```

## 4. Install dependencies

```bash
pip install -r requirements.txt
```

## 5. Verify installation

```bash
python3 vapt.py --help
```

---

# ▶️ Usage

## Scan an IP address

```bash
python3 vapt.py scan --target 192.168.1.10
```

## Scan a hostname

```bash
python3 vapt.py scan --target example.local
```

## Scan an HTTP target

```bash
python3 vapt.py scan --target http://example.local
```

## Scan an HTTPS target

```bash
python3 vapt.py scan --target https://example.com
```

## Display project version

```bash
python3 vapt.py version
```

> Only use targets that you own or have explicit authorization to assess.

---

# 🛠️ Requirements

### Software

- Python 3
- Nmap
- pip
- Linux recommended for the current implementation

Python dependencies are listed in:

```text
requirements.txt
```

### Install Nmap

For Kali/Debian-based systems:

```bash
sudo apt update
sudo apt install nmap
```

Verify:

```bash
nmap --version
```

---

# 🧪 Recommended Laboratory Targets

For development and security testing, use intentionally vulnerable systems in an isolated or controlled environment.

Recommended platforms include:

- **Metasploitable 2** — network/service vulnerability testing
- **OWASP Juice Shop** — modern web application security testing
- **DVWA** — classic web vulnerability testing
- **OWASP WebGoat** — web security training
- **PortSwigger Web Security Academy** — individual web security labs

Do not scan arbitrary public systems without explicit authorization.

---

# 📊 Example Assessment

A controlled laboratory assessment can follow this process:

```text
Target
  │
  ├── Nmap Discovery
  │      ├── FTP
  │      ├── SSH
  │      ├── HTTP
  │      ├── SMB
  │      ├── MySQL
  │      ├── IRC
  │      ├── Tomcat
  │      └── Other detected services
  │
  ├── Network Vulnerability Assessment
  │
  ├── Web Security Assessment
  │
  ├── Evidence Collection
  │
  ├── Risk Prioritization
  │
  └── PDF Security Report
```

---

# ⚙️ Configuration

Configuration is stored in:

```text
config/default.json
```

Example configuration areas:

```json
{
    "project": {
        "name": "VULNSCOPE",
        "version": "0.1.0"
    },
    "scan": {
        "timeout": 300,
        "max_threads": 10
    },
    "modules": {
        "discovery": true,
        "web_scanner": true,
        "network_scanner": true,
        "validation": true,
        "reporter": true
    },
    "output": {
        "directory": "./reports",
        "formats": ["pdf"]
    },
    "scope": {
        "allowed_targets": [],
        "excluded_targets": []
    }
}
```

Configuration can control:

- Scan timeout
- Module enable/disable state
- Output directory
- Output format
- Allowed targets
- Excluded targets

---

# 🎯 Scope & Target Validation

VULNSCOPE supports validation for:

- IPv4 addresses
- IPv6 addresses
- Hostnames
- HTTP URLs
- HTTPS URLs
- Configurable allowed targets
- Configurable excluded targets

Excluded targets take priority over allowed targets.

This helps prevent accidental assessment of systems outside the configured scope.

---

# 🔍 Finding Structure

Findings can contain:

```text
Title
Severity
Description
Host
Port
Service
Product
Version
CPE
CVE
CVSS
Priority
Detection Method
Confidence
Evidence
Remediation
References
```

The same finding model can be used across the vulnerability engine, terminal output, risk prioritization, and PDF reporting layers.

---

# 📂 Output

### Runtime logs

```text
reports/vapt.log
```

### Generated reports

```text
reports/NEXUS-VAPT_Report_<target>_<timestamp>.pdf
```

Generated reports and logs should normally remain local and should be excluded from Git when they contain sensitive assessment information.

---

# 📄 Sample PDF Report

VULNSCOPE can generate structured security assessment reports containing:

- Executive Summary
- Target Information
- Network Discovery
- Vulnerability Assessment
- Web Security Assessment
- Risk Assessment
- Severity Distribution
- Evidence
- Remediation Recommendations
- Methodology
- Conclusion


# 🔐 Security Philosophy

VULNSCOPE follows a staged security assessment model:

```text
Discover
   ↓
Detect
   ↓
Collect Evidence
   ↓
Prioritize
   ↓
Report
```

The framework focuses on identifying and prioritizing security issues rather than automatically exploiting targets.

This makes it suitable for:

- Security learning
- VAPT practice
- Controlled lab environments
- Cybersecurity portfolio development
- Vulnerability assessment research

---

# ⚠️ Current Limitations

VULNSCOPE `0.1.0` is an **early-stage VAPT framework** and should not be considered a replacement for mature commercial or open-source security assessment platforms.

Current limitations include:

- Vulnerability coverage is limited to implemented checks.
- Many network findings rely on service/version information.
- Important findings should be manually validated.
- Web checks are intentionally lightweight.
- Full browser-level application testing is not currently provided.
- Authentication testing is limited compared with a full authenticated penetration test.
- Results may contain false positives or false negatives.
- Nmap OS/service identification is not guaranteed to be perfectly accurate.
- The current CLI is primarily designed around a single target per assessment.
- The project currently focuses on PDF reporting rather than a web dashboard.
- Automated exploitation is not a goal of the current release.

> **Always validate important findings before treating them as confirmed vulnerabilities.**

---

---

# 🗺️ Roadmap

Future improvements may include:

- [ ] Expanded CVE/service coverage
- [ ] Improved technology fingerprinting
- [ ] Improved authenticated web testing
- [ ] More robust XSS detection
- [ ] Improved SQL injection detection
- [ ] CVSS vector support
- [ ] JSON reporting
- [ ] HTML reporting
- [ ] Automated unit tests
- [ ] Automated integration tests
- [ ] Plugin architecture
- [ ] Scan profiles
- [ ] Configurable scan intensity
- [ ] Improved evidence collection
- [ ] Multi-target assessment support
- [ ] Web-based reporting dashboard
- [ ] Improved false-positive reduction

---

---

# 📚 Learning Objectives

This project was developed to explore practical cybersecurity concepts including:

- Network reconnaissance
- Service enumeration
- Vulnerability assessment
- Web application security
- OWASP security concepts
- CVE correlation
- CVSS-based risk assessment
- Evidence collection
- Security reporting
- Python security tooling
- Modular security-tool architecture

---

# 👨‍💻 Author

## Utsav Thakur

**Cybersecurity / VAPT Project**
- Email id: utsavthakur448@gmail.com
- GitHub: https://github.com/utsavthakur448
- LinkedIn: https://www.linkedin.com/in/utsavthakur123

---

---

## ⭐ If you find this project useful

If VULNSCOPE helps you learn about vulnerability assessment or cybersecurity tooling, consider giving the repository a ⭐ on GitHub.

**Built for learning. Built for security. Built for authorized testing.**
