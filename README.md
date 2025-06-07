# PrivDiff - macOS Privilege Recon Tool

PrivDiff is a privilege and configuration recon tool for macOS systems designed to find privilege escalations and misconfigurations with modular scans and diffing.

## Features
 Detect writable SUID binaries
 Analyze user crontabs for suspicious jobs
 Check launch agents and daemons for anomalies
 Export reports in .JSON, .TXT, .CSV
 External YAML config
 Trace logging with base64 encoded dumps
 Multi-threaded scanning with timing.

## Installation
```bash
git clone https://github.com/yourusername/privdiff.git
cd privdiff
pip install -r requirements.txt
```
## Usage
```bash
python3 privdiff.py
```

Options for export format:

```bash
python3 privdiff.py --export json|txt|csv
