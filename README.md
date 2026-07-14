# 🛡️ AegisGuard – Portable Offline Cybersecurity Analyzer

> **A lightweight, offline cybersecurity monitoring and threat analysis toolkit for air-gapped and restricted environments.**

AegisGuard is a portable cybersecurity solution that enables organizations to **collect, analyze, and visualize security events without requiring internet connectivity**. Designed for digital forensic investigations, security auditing, and offline SOC environments, the system operates entirely from a USB drive using two standalone desktop applications.

---

# 📌 Project Overview

AegisGuard follows a two-stage architecture:

1. **Collector** – Collects security logs from Windows and Linux endpoints and converts them into a standardized JSON format.
2. **Analyzer** – Processes collected logs, correlates events, detects potential threats, stores results in SQLite, and visualizes security insights through an offline dashboard.

The applications communicate **only through JSON log files stored on a USB drive**, eliminating the need for network communication or cloud services.

---

# 🏗️ System Architecture

```text
                ┌────────────────────────────┐
                │   Victim Machines (N)      │
                │ Windows / Linux Endpoints  │
                └─────────────┬──────────────┘
                              │
                    Collector.exe
                              │
             Collect & Normalize Logs
                              │
                    Standard JSON Files
                              │
                     USB Flash Drive
                              │
                Transfer to Analyst PC
                              │
                    Analyzer.exe
                              │
         Event Correlation & Threat Detection
                              │
                       SQLite Database
                              │
               Offline Dashboard & Reports
```

---

# ✨ Features

## Collector

- Historical log collection
- Optional real-time monitoring
- Windows Event Log support
- Linux log collection
- Automatic JSON normalization
- USB storage support
- Cross-platform architecture
- Offline operation

### Windows Sources

- Security Logs
- System Logs
- Application Logs
- Windows Defender Logs
- PowerShell Logs

### Linux Sources

- `/var/log/auth.log`
- `/var/log/audit/audit.log`
- `/var/log/syslog`

---

## Analyzer

- JSON log ingestion
- Event validation
- Duplicate detection
- Rule-based threat detection
- Event correlation
- Risk scoring
- Recommendation engine
- SQLite storage
- Interactive dashboard
- Offline reporting

---

# 📂 Project Structure

```text
AegisGuard/
│
├── collector/
│   ├── main.py                     # Entry point
│   │
│   ├── collectors/
│   │   ├── windows/
│   │   │   ├── eventlog_reader.py
│   │   │   ├── realtime_monitor.py
│   │   │   └── __init__.py
│   │   │
│   │   ├── linux/
│   │   │   ├── reader.py
│   │   │   ├── monitor.py
│   │   │   └── __init__.py
│   │   │
│   │   └── collector_manager.py    # Chooses Windows/Linux collector
│   │
│   ├── parsers/
│   │   ├── windows/
│   │   │   ├── parser.py
│   │   │   └── __init__.py
│   │   │
│   │   ├── linux/
│   │   │   ├── parser.py
│   │   │   └── __init__.py
│   │   │
│   │   └── parser_manager.py
│   │
│   ├── schema/
│   │   ├── formatter.py
│   │   └── event_schema.py
│   │
│   ├── storage/
│   │   ├── json_writer.py
│   │   ├── usb_manager.py
│   │   └── checksum.py
│   │
│   ├── utils/
│   │   ├── logger.py
│   │   ├── platform_detector.py
│   │   └── config.py
│   │
│   └── output/
│       └── logs.json
│
├── analyzer/
│   ├── main.py
│   ├── ingestion/
│   │   ├── loader.py
│   │   ├── validator.py
│   │   ├── deduplicator.py
│   │   └── importer.py
│   │
│   ├── detection/
│   │   ├── engine.py
│   │   ├── correlator.py
│   │   ├── severity.py
│   │   ├── recommender.py
│   │   └── rules/
│   │       ├── brute_force.py
│   │       ├── privilege_escalation.py
│   │       ├── account_compromise.py
│   │       ├── suspicious_process.py
│   │       └── file_tampering.py
│   │
│   ├── alerts/
│   │   ├── alert.py
│   │   └── manager.py
│   │
│   ├── reports/
│   │   ├── pdf_export.py
│   │   └── csv_export.py
│   │
│   └── database/
│       ├── db_manager.py
│       └── schema.sql
├── common/
├── config/
├── docs/
├── tests/
├── requirements.txt
├── build_collector.spec
├── build_analyzer.spec
└── README.md
```

---

# 📄 Standard Event Schema

Every collected event is normalized into a common JSON format.

```json
{
  "timestamp": "",
  "hostname": "",
  "os": "",
  "category": "",
  "event_type": "",
  "severity": "",
  "description": "",
  "username": "",
  "source_ip": "",
  "destination_ip": "",
  "process": "",
  "resource": "",
  "message": ""
}
```

This standardized schema ensures compatibility between all supported operating systems.

---

# 🔍 Threat Detection

The Analyzer uses rule-based detection and event correlation to identify suspicious activities.

### Authentication

- Successful Login
- Failed Login
- Multiple Failed Logins
- SSH Brute Force
- Account Compromise
- Password Change
- User Creation
- User Deletion

### Privilege Events

- Sudo Execution
- Administrator Login
- Privilege Escalation

### File Activity

- File Creation
- File Modification
- File Deletion
- File Rename

### System Events

- Service Started
- Service Stopped
- Firewall Disabled
- Firewall Enabled
- USB Connected
- USB Removed

### Network Events

- SSH Login
- Remote Desktop Login
- Suspicious Port Access
- Unknown Network Connections

---

# 🚨 Severity Levels

| Level | Risk Score |
|---------|-----------|
| Low | 20 |
| Medium | 50 |
| High | 80 |
| Critical | 100 |

---

# 💡 Recommendations

For every detected threat, AegisGuard generates mitigation guidance.

Example:

```text
Threat:
SSH Brute Force Attack

Severity:
High

Recommendations:
• Block the source IP
• Enable Fail2Ban
• Review SSH logs
• Reset affected credentials
```

---

# 🗄️ Database

The Analyzer stores processed information in an offline SQLite database.

Tables include:

- Events
- Alerts
- Recommendations
- Hosts
- Users
- Statistics

---

# 📊 Dashboard

The PySide6 desktop dashboard provides:

- Security Overview
- Event Explorer
- Alert Management
- Threat Timeline
- Host Statistics
- User Activity
- Search & Filters
- Report Generation

Charts include:

- Alerts by Severity
- Event Categories
- Authentication Timeline
- Top Source IPs
- Daily Event Trends
- Threat Distribution

---

# 📑 Report Export

Generate offline reports in:

- PDF
- CSV
- JSON

Reports include:

- Executive Summary
- Event Statistics
- Threat Analysis
- Risk Distribution
- Security Recommendations

---

# 🔒 Offline Design

AegisGuard is designed for environments where internet connectivity is unavailable or prohibited.

- No cloud services
- No telemetry
- No remote servers
- No API dependencies
- No internet access required

All processing is performed locally.

---

# 🛠️ Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.11 |
| GUI | PySide6 |
| Database | SQLite |
| Charts | Qt Charts |
| Windows Logs | pywin32 |
| Linux Monitoring | watchdog / auditd / tail |
| Packaging | PyInstaller |
| PDF Reports | ReportLab |

---

# 🚀 Build Instructions

Clone the repository:

```bash
git clone https://github.com/<your-username>/AegisGuard.git
cd AegisGuard
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it:

### Windows

```bash
.venv\Scripts\activate
```

### Linux

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# 📦 Packaging

Build the applications using PyInstaller.

Collector:

```bash
pyinstaller build_collector.spec
```

Analyzer:

```bash
pyinstaller build_analyzer.spec
```

Generated executables:

```
dist/
├── Collector.exe
└── Analyzer.exe
```

---

# 🧪 Testing

Run unit tests:

```bash
pytest tests/
```

---

# 🎯 Future Enhancements

- MITRE ATT&CK technique mapping
- YARA rule integration
- Sigma rule support
- Offline IOC database
- Machine learning anomaly detection
- Multi-language support
- Automated USB synchronization

---

# 👥 Contributors

Developed as a Final Year Cybersecurity Project.

**Project:** AegisGuard – Portable Offline Cybersecurity Analyzer

---

# 📄 License

This project is intended for **educational and research purposes**. Ensure all security testing and log collection are performed only on systems you own or are authorized to assess.