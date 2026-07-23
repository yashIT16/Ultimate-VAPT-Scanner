# Ultimate VAPT Scanner

An automated Vulnerability Assessment and Penetration Testing (VAPT) framework with a web interface. This tool chains multiple security scanning tools to perform comprehensive reconnaissance and exploitation against target infrastructure.

## Features

- **Web Interface**: Easy-to-use Flask-based GUI to launch and monitor scans.
- **Tool Chaining**: Intelligently chains output from one tool as input to the next (e.g., passing discovered directories to SQLMap).
- **Anonymous Mode**: Option to route traffic through Tor (Proxychains).
- **PDF Reporting**: Automatically generates detailed VAPT reports with AI-summarized executive overviews and PoC screenshots.

## Integrated Tools

- **Wafw00f**: WAF and Firewall detection
- **Subfinder & Httpx**: Subdomain enumeration and live host probing
- **Nmap**: Advanced network discovery and evasion
- **Gobuster**: Web directory evasion and discovery
- **Nuclei**: Surgical vulnerability exploitation
- **SQLMap**: Targeted database exploitation
- **Hydra**: Targeted authentication cracking
- **DNS & Whois**: Information gathering

## Setup & Installation

### Using Docker (Recommended)

1. Ensure Docker and Docker Compose are installed.
2. Build and run the container:
   ```bash
   docker-compose up --build
   ```
3. Access the web interface at `http://localhost:5000`

### Manual Installation

1. Install system dependencies (nmap, gobuster, nuclei, sqlmap, hydra, wafw00f, proxychains4, etc.).
2. Install Python requirements:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python app.py
   ```

## Disclaimer
This tool is for educational purposes and authorized penetration testing only. Do not use this tool against infrastructure you do not own or have explicit permission to test.
