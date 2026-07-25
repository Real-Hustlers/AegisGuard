# 🛡️ AegisGuard – Portable Offline Cybersecurity Analyzer

> **A lightweight, offline cybersecurity monitoring and threat analysis toolkit for air-gapped and restricted environments.**

AegisGuard is a portable cybersecurity solution that enables organizations to **collect, analyze, and visualize security events without requiring internet connectivity**. Designed for digital forensic investigations, security auditing, and offline SOC environments, the system operates entirely from a USB drive using two standalone desktop applications.

---

# 📌 Project Overview

AegisGuard is a portable, offline cybersecurity monitoring and incident response platform designed for air-gapped and restricted environments. The system enables organizations to collect, analyze, correlate, and respond to security events without requiring internet connectivity.

The project follows a modular pipeline consisting of:

1. **Collector**
   - Collects security logs from Windows and Linux endpoints.
   - Normalizes logs into a common JSON schema.
   - Stores collected logs on a portable USB drive.

2. **Analyzer**
   - Merges and validates collected logs.
   - Performs Machine Learning-based threat classification.
   - Maps detected threats to the MITRE ATT&CK framework.
   - Correlates related events into multi-stage attack incidents.
   - Generates structured incident reports with risk scores.
   - Supports offline response playbooks and automated response simulation.
   - Stores results in SQLite and visualizes them through an interactive offline dashboard.

The Collector and Analyzer communicate exclusively through standardized JSON files, making the entire platform portable, offline, and suitable for digital forensic investigations, cyber ranges, educational laboratories, and isolated Security Operations Centers (SOCs).

---

# 🏗️ System Architecture

```text
              ┌──────────────────────────────┐
              │ Windows / Linux Endpoints    │
              └──────────────┬───────────────┘
                             │
                    Collector Application
                             │
             Collect & Normalize Security Logs
                             │
                  Standardized JSON Files
                             │
                      USB Flash Drive
                             │
                    Analyzer Application
                             │
                     Merge & Validate Logs
                             │
                Machine Learning Classifier
                             │
                Threat Score & Threat Level
                             │
                MITRE ATT&CK Mapping Engine
                             │
                 Event Correlation Engine
                             │
                 Multi-stage Attack Detection
                             │
                  Incident Generation Engine
                             │
               Response Playbook Assignment
                             │
            Offline Response Simulation Engine
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

- Log merging and normalization
- JSON log ingestion
- Machine Learning-based threat classification
- Rule-based threat scoring
- MITRE ATT&CK technique mapping
- Event correlation engine
- Multi-stage attack detection
- Incident generation
- SQLite database storage
- Offline incident response workflow
- Interactive dashboard
- Offline reporting

---

# 📂 Project Structure

```text
AegisGuard/
│
├── collector/
│   ├── collectors/
│   ├── parsers/
│   ├── schema/
│   ├── storage/
│   ├── utils/
│   ├── output/
│   └── collector.py
│
├── backend/
│   └── analyzer/
│       ├── ingestion/
│       │   ├── import_merge.py
│       │   ├── classifier.py
│       │   ├── correlation_engine.py
│       │   ├── mitre_mapper.py
│       │   ├── output/
│       │   └── test/
│       │
│       ├── mysql/
│       │   ├── merge_log_sql.py
│       │   └── schema.sql
│       │
│       ├── output/
│       │   ├── merged_logs.json
│       │   ├── classified_logs.json
│       │   ├── incidents.json
│       │   └── incident_reports/
│       │
│       ├── app.py
│       ├── service.py
│       ├── database.py
│       ├── incident_response.py
│       └── settings.py
│
├── ML Aegis/
│   └── ml/
│       ├── model.pkl
│       ├── label_encoder.pkl
│       ├── train_model.py
│       └── dataset.csv
│
├── static/
│   ├── css/
│   ├── js/
│   └── images/
│
├── templates/
│   └── index.html
│
├── docs/
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

# 🔍 Threat Detection & Correlation

AegisGuard combines Machine Learning classification with rule-based event correlation to detect complex attack scenarios.

## Machine Learning Classification

Each incoming event is classified into a threat category using a trained ML model and assigned:

- Threat Prediction
- Confidence Score
- Threat Score
- Threat Level
- MITRE ATT&CK Mapping

## Event Correlation Engine

The Correlation Engine groups related events occurring within configurable time windows to identify multi-stage attacks.

Currently supported correlation patterns include:

| Rule | Attack |
|------|---------|
| Rule 1 | Brute Force Attack |
| Rule 2 | Privilege Escalation |
| Rule 3 | Malware Execution |
| Rule 4 | Reconnaissance |
| Rule 5 | Lateral Movement |
| Rule 6 | Persistence |
| Rule 7 | Data Exfiltration |
| Rule 8 | Ransomware Activity |

Each detected attack generates an incident containing:

- Incident ID
- Risk Score
- Severity
- Timeline
- Related Logs
- MITRE ATT&CK Technique
- Machine Learning Prediction

---

# ⚡ Incident Response Workflow

Each detected incident follows an automated offline response workflow.

Raw Logs
↓
Collector
↓
Merged Logs
↓
ML Classification
↓
Correlation Engine
↓
Incident Generation
↓
MITRE ATT&CK Mapping
↓
Response Playbook
↓
Incident Response Package
↓
Dashboard


## Each incident contains:

- Incident metadata
- Timeline
- Threat score
- MITRE ATT&CK mapping
- Suggested response playbook
- Remediation commands
- Related evidence

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

- security_logs
- incidents
- response_logs
- settings

---

# 📊 Dashboard

The offline dashboard provides:

- Security Overview
- Threat Timeline
- Incident Explorer
- MITRE ATT&CK Mapping
- Threat Severity Distribution
- Host Activity
- Authentication Activity
- Top Source IPs
- Event Explorer
- Incident Details
- Response Logs
- Automated Response Status

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

# 🎥 Demonstration Workflow

The project demonstration follows the complete Security Operations Center (SOC) workflow:

1. Collect security logs from Windows/Linux endpoints.
2. Merge and normalize collected logs.
3. Perform Machine Learning-based threat classification.
4. Assign threat scores and MITRE ATT&CK mappings.
5. Correlate related events into attack incidents.
6. Generate structured incident reports.
7. Load incidents into the offline dashboard.
8. Display recommended response playbooks.
9. Simulate automated incident response actions.
10. Review response logs and mitigation status.

The entire workflow operates without requiring an internet connection.

---

# 🎯 Future Enhancements

The current implementation focuses on offline log analysis and automated incident generation. Future work includes:

- Graph-based event correlation
- Sigma rule support
- YARA rule integration
- Offline IOC database
- Threat intelligence synchronization
- Machine Learning-based anomaly detection
- UEBA (User & Entity Behavior Analytics)
- Multi-host attack graph visualization
- Digital forensic artifact collection
- Portable incident response toolkit
- Automatic PDF incident report generation
- Multi-language dashboard support

---

# ✅ Current Capabilities

- Offline operation
- Cross-platform log collection
- Machine Learning threat classification
- MITRE ATT&CK mapping
- Threat scoring
- Event correlation
- Multi-stage attack detection
- Incident generation
- SQLite backend
- Offline dashboard
- Response playbook support
- Automated response simulation

---

# 👥 Contributors

Developed as a Final Year Cybersecurity Project.

**Project:** AegisGuard – Portable Offline Cybersecurity Analyzer

---

# 📄 License

This project is intended for **educational and research purposes**. Ensure all security testing and log collection are performed only on systems you own or are authorized to assess.