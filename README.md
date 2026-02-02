<div align="center">

# 💾 Network Config Backup Tool

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Netmiko](https://img.shields.io/badge/Netmiko-Multi--Vendor-00ADD8?style=for-the-badge&logo=cisco&logoColor=white)](https://github.com/ktbyers/netmiko)
[![Git](https://img.shields.io/badge/Git-Version_Control-F05032?style=for-the-badge&logo=git&logoColor=white)](https://git-scm.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**Automated network configuration backup with Git versioning, compliance checking, and change detection**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Supported Devices](#-supported-devices)

---

</div>

## 🎯 Overview

The **Network Config Backup Tool** provides enterprise-grade automated configuration backup for multi-vendor network environments. It combines Netmiko for device connectivity, Git for version control, and intelligent diff analysis for change detection.

### Why This Tool?

| Challenge | Solution |
|-----------|----------|
| Manual backups are inconsistent | Scheduled automated backups |
| No version history | Git-based versioning with full history |
| Change tracking is difficult | Automated diff reports and notifications |
| Multi-vendor complexity | Unified interface for Cisco, Juniper, Arista, Palo Alto |
| Compliance verification | Built-in compliance rule engine |

---

## ⚡ Features

```
┌─────────────────────────────────────────────────────────────────┐
│                    CORE CAPABILITIES                            │
├─────────────────────────────────────────────────────────────────┤
│  📦 BACKUP          │  📊 ANALYSIS        │  🔔 ALERTS          │
│  ─────────────────  │  ─────────────────  │  ─────────────────  │
│  • Running Config   │  • Diff Detection   │  • Email Reports    │
│  • Startup Config   │  • Change Summary   │  • Slack Webhook    │
│  • Full State       │  • Compliance Check │  • Teams Notify     │
│  • Custom Commands  │  • Security Audit   │  • Syslog           │
├─────────────────────────────────────────────────────────────────┤
│  🔄 VERSION CONTROL │  📅 SCHEDULING      │  🔐 SECURITY        │
│  ─────────────────  │  ─────────────────  │  ─────────────────  │
│  • Git Integration  │  • Cron Jobs        │  • Encrypted Creds  │
│  • Branch per Site  │  • Interval Based   │  • SSH Key Auth     │
│  • Commit History   │  • On-Demand        │  • Vault Support    │
│  • Tag Releases     │  • Change Triggered │  • Audit Logging    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🖥️ Supported Devices

| Vendor | Platforms | Connection |
|--------|-----------|------------|
| **Cisco** | IOS, IOS-XE, IOS-XR, NX-OS, ASA | SSH |
| **Juniper** | Junos (SRX, EX, MX, QFX) | SSH/NETCONF |
| **Arista** | EOS | SSH/eAPI |
| **Palo Alto** | PAN-OS | SSH/API |
| **Fortinet** | FortiOS | SSH |
| **HP/Aruba** | ProCurve, ArubaOS | SSH |
| **Linux** | Any SSH-accessible server | SSH |

---

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/tamersaid2022/network-config-backup.git
cd network-config-backup

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Initialize Git repository for backups
cd backups && git init
```

### Requirements

```txt
netmiko>=4.2.0
paramiko>=3.3.0
pyyaml>=6.0
gitpython>=3.1.0
cryptography>=41.0.0
jinja2>=3.1.0
rich>=13.0.0
python-dotenv>=1.0.0
schedule>=1.2.0
requests>=2.31.0
```

---

## 🚀 Usage

### Quick Start

```python
from network_backup import NetworkBackup

# Initialize backup manager
backup = NetworkBackup(
    inventory="inventory.yaml",
    backup_dir="./backups",
    git_enabled=True
)

# Backup all devices
results = backup.backup_all()

# Backup specific device
backup.backup_device("core-router-01")

# Generate change report
report = backup.diff_report(days=7)
```

### Command Line Interface

```bash
# Backup all devices in inventory
python network_backup.py backup --all

# Backup specific device
python network_backup.py backup --device core-router-01

# Backup by group/tag
python network_backup.py backup --group datacenter

# Show recent changes
python network_backup.py diff --days 7

# Run compliance check
python network_backup.py compliance --rules rules/security.yaml

# Schedule backups (runs every 6 hours)
python network_backup.py schedule --interval 6h
```

---

## 📋 Configuration

### Inventory File (inventory.yaml)

```yaml
# inventory.yaml
---
defaults:
  username: admin
  timeout: 30
  
devices:
  core-router-01:
    host: 192.168.1.1
    device_type: cisco_ios
    groups: [datacenter, core]
    
  core-router-02:
    host: 192.168.1.2
    device_type: cisco_ios
    groups: [datacenter, core]
    
  firewall-01:
    host: 192.168.1.10
    device_type: paloalto_panos
    groups: [datacenter, security]
    
  switch-access-01:
    host: 192.168.2.1
    device_type: cisco_ios
    groups: [access, floor1]
    
groups:
  datacenter:
    backup_commands:
      - show running-config
      - show version
      - show inventory
      
  security:
    backup_commands:
      - show config running
      - show system info
```

### Compliance Rules (rules/security.yaml)

```yaml
# rules/security.yaml
---
name: "Security Baseline"
version: "1.0"

rules:
  - name: "SSH Version 2 Required"
    pattern: "ip ssh version 2"
    required: true
    severity: HIGH
    remediation: "Configure 'ip ssh version 2'"
    
  - name: "No Telnet"
    pattern: "transport input telnet"
    prohibited: true
    severity: CRITICAL
    remediation: "Remove telnet from line configurations"
    
  - name: "Enable Secret Configured"
    pattern: "enable secret"
    required: true
    severity: HIGH
    
  - name: "NTP Configured"
    pattern: "ntp server"
    required: true
    severity: MEDIUM
    
  - name: "Logging Enabled"
    pattern: "logging buffered"
    required: true
    severity: MEDIUM
```

---

## 📊 Sample Outputs

### Backup Summary

```
╔══════════════════════════════════════════════════════════════════╗
║              NETWORK CONFIGURATION BACKUP REPORT                 ║
╠══════════════════════════════════════════════════════════════════╣
║  Timestamp:    2024-01-15 14:30:00                               ║
║  Total Devices: 25                                               ║
║  Successful:    23                                               ║
║  Failed:        2                                                ║
╠══════════════════════════════════════════════════════════════════╣
║  BACKUP STATUS                                                   ║
║  ├─ core-router-01      ✅ SUCCESS    2.3 KB   Changed          ║
║  ├─ core-router-02      ✅ SUCCESS    2.1 KB   No Change        ║
║  ├─ firewall-01         ✅ SUCCESS    45 KB    Changed          ║
║  ├─ switch-access-01    ❌ FAILED     Timeout                   ║
║  └─ switch-access-02    ✅ SUCCESS    1.8 KB   No Change        ║
╠══════════════════════════════════════════════════════════════════╣
║  GIT COMMIT: a3f7c2d - "Automated backup 2024-01-15"            ║
╚══════════════════════════════════════════════════════════════════╝
```

### Change Detection Report

```
╔══════════════════════════════════════════════════════════════════╗
║              CONFIGURATION CHANGE REPORT (7 Days)                ║
╠══════════════════════════════════════════════════════════════════╣
║  Device: core-router-01                                          ║
║  Changes: 3 commits                                              ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  [2024-01-15 10:30] Added VLAN 100                              ║
║  ──────────────────────────────────────────────────────────────  ║
║  + vlan 100                                                      ║
║  +  name PRODUCTION                                              ║
║  + interface Vlan100                                             ║
║  +  ip address 10.100.0.1 255.255.255.0                         ║
║                                                                  ║
║  [2024-01-14 16:45] Updated ACL                                 ║
║  ──────────────────────────────────────────────────────────────  ║
║  - access-list 101 permit ip 10.0.0.0 0.255.255.255 any        ║
║  + access-list 101 permit ip 10.0.0.0 0.0.255.255 any          ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

### Compliance Report

```
╔══════════════════════════════════════════════════════════════════╗
║              COMPLIANCE AUDIT REPORT                             ║
╠══════════════════════════════════════════════════════════════════╣
║  Baseline:    Security Baseline v1.0                             ║
║  Devices:     25 scanned                                         ║
║  Compliant:   20 (80%)                                           ║
║  Non-Compliant: 5 (20%)                                          ║
╠══════════════════════════════════════════════════════════════════╣
║  FINDINGS                                                        ║
║                                                                  ║
║  🔴 CRITICAL (2)                                                 ║
║  ├─ switch-access-05: Telnet enabled on VTY lines               ║
║  └─ switch-access-12: Telnet enabled on VTY lines               ║
║                                                                  ║
║  🟠 HIGH (3)                                                     ║
║  ├─ switch-access-03: SSH version 1 in use                      ║
║  ├─ switch-access-07: No enable secret configured               ║
║  └─ switch-access-09: SSH version 1 in use                      ║
║                                                                  ║
║  🟡 MEDIUM (5)                                                   ║
║  └─ 5 devices missing NTP configuration                         ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## 🏗️ Project Structure

```
network-config-backup/
├── network_backup.py        # Main backup script
├── inventory.yaml           # Device inventory
├── config/
│   └── settings.yaml        # Global settings
├── rules/
│   ├── security.yaml        # Security compliance rules
│   ├── best-practices.yaml  # Best practice checks
│   └── pci-dss.yaml        # PCI-DSS requirements
├── backups/                 # Git-versioned backups
│   ├── datacenter/
│   │   ├── core-router-01.cfg
│   │   └── core-router-02.cfg
│   └── branch/
│       └── branch-router-01.cfg
├── reports/
│   └── compliance_YYYYMMDD.html
├── templates/
│   └── report.html.j2       # Report template
└── requirements.txt
```

---

## 🔐 Security Best Practices

| Practice | Implementation |
|----------|----------------|
| **Credential Storage** | Use environment variables or HashiCorp Vault |
| **SSH Keys** | Prefer key-based authentication over passwords |
| **Encryption** | Encrypt backup files at rest |
| **Access Control** | Restrict backup directory permissions |
| **Audit Trail** | Git commit history provides full audit trail |
| **Secrets in Git** | Never commit credentials - use .gitignore |

### Environment Variables

```bash
# .env file (never commit this!)
NETWORK_USER=admin
NETWORK_PASSWORD=SecureP@ss123
VAULT_TOKEN=hvs.xxxxxxxxxxxxx
SLACK_WEBHOOK=https://hooks.slack.com/...
```

---

## 📅 Scheduling Options

### Cron Job (Linux)

```bash
# Run every 6 hours
0 */6 * * * /path/to/venv/bin/python /path/to/network_backup.py backup --all

# Daily at 2 AM
0 2 * * * /path/to/venv/bin/python /path/to/network_backup.py backup --all
```

### Built-in Scheduler

```bash
# Run continuously with interval
python network_backup.py schedule --interval 6h --notify slack
```

### Windows Task Scheduler

```powershell
# Create scheduled task
schtasks /create /tn "NetworkBackup" /tr "python C:\backup\network_backup.py backup --all" /sc hourly /mo 6
```

---

## 🔔 Notifications

### Slack Integration

```yaml
# config/settings.yaml
notifications:
  slack:
    enabled: true
    webhook_url: ${SLACK_WEBHOOK}
    channel: "#network-alerts"
    on_change: true
    on_failure: true
```

### Email Alerts

```yaml
notifications:
  email:
    enabled: true
    smtp_server: smtp.company.com
    recipients:
      - netops@company.com
    on_change: true
    on_failure: true
    daily_summary: true
```

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

### 👨‍💻 Author

**Tamer Khalifa** - *Network Automation Engineer*

[![CCIE](https://img.shields.io/badge/CCIE-68867-1BA0D7?style=flat-square&logo=cisco&logoColor=white)](https://www.cisco.com/c/en/us/training-events/training-certifications/certifications/expert.html)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat-square&logo=linkedin)](https://linkedin.com/in/tamerkhalifa2022)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat-square&logo=github)](https://github.com/tamersaid2022)

---

⭐ **Star this repo if you find it useful!** ⭐

</div>
