# Python Security Tools 🛡️

A collection of ethical security tools written in Python for penetration testing, defensive security, and automation.

## 📦 Tools Included

| Tool | Description |
|------|------------|
| [Port Scanner](#port-scanner) | Scan for open ports on a target host |
| [Directory Bruteforcer](#directory-bruteforcer) | Discover hidden web directories |
| [Password Checker](#password-checker) | Check password against breached databases |
| [Log Analyzer](#log-analyzer) | Detect suspicious activity in log files |
| [Backup Checker](#backup-checker) | Verify backup freshness and existence |

## 🚀 Getting Started

### Prerequisites
- Python 3.6+
- pip package manager

### Installation
```bash
git clone https://github.com/yourusername/security-tools.git
cd security-tools
pip install -r requirements.txt
```

## Tools Documentation
# Port Scanner
```bash
## python port_scanner.py
```
Scans a target host for open ports using multithreading.

Options:

-t or --target: Target IP/hostname (required)

-s or --start: Starting port (default: 1)

-e or --end: Ending port (default: 1024)
