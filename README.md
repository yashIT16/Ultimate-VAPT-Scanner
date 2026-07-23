# Ultimate VAPT Scanner

An advanced, automated Vulnerability Assessment and Penetration Testing (VAPT) framework equipped with a user-friendly Flask-based web interface. This tool chains multiple security scanning utilities together to perform comprehensive reconnaissance, intelligent vulnerability detection, and targeted exploitation against web infrastructure.

---

## 🌟 Key Features

- **Intuitive Web Interface**: A sleek, easy-to-use GUI to configure targets, select scan modules, and monitor live progress via server-sent events (SSE).
- **Intelligent Tool Chaining**: Dynamically uses the output of one tool as the input for the next. For example:
  - Discovered open ports trigger specific brute-force attacks.
  - Hidden directories discovered by Gobuster are automatically forwarded to SQLMap for database injection testing.
- **Anonymous Mode**: Built-in support to route all scanning traffic through the Tor network using `proxychains4` to prevent IP blocking and ensure anonymity.
- **Executive Reporting**: Automatically generates detailed PDF reports containing live PoC screenshots and an AI-summarized executive overview of critical findings.
- **WAF Evasion**: Automatically detects Web Application Firewalls (WAF) and adapts scan speeds and payloads to minimize detection.

---

## 🛠️ Integrated Modules

The scanner leverages industry-standard tools, orchestrated through a single interface:

1. **Wafw00f**: Pre-flight WAF and Firewall detection.
2. **Subfinder & Httpx**: Subdomain enumeration and live-host verification.
3. **Nmap**: Advanced network discovery, port scanning, and evasion.
4. **Gobuster**: Web directory brute-forcing and hidden path discovery.
5. **Nuclei**: Surgical, template-based vulnerability exploitation.
6. **SQLMap**: Targeted database exploitation on discovered endpoints.
7. **Hydra**: Targeted authentication cracking (FTP, SSH, etc.) on open ports.
8. **DNS & Whois**: Passive information gathering and infrastructure mapping.

---

## 🚀 Setup & Installation

You can run the Ultimate VAPT Scanner using Docker (highly recommended) or install it manually on a Linux/Kali machine.

### Method 1: Using Docker (Recommended)

Using Docker ensures all dependencies (Nmap, SQLMap, Nuclei, Chrome for screenshots, etc.) are perfectly configured in an isolated environment without cluttering your host machine.

1. **Clone the repository** (if you haven't already):
   ```bash
   git clone https://github.com/yashIT16/Ultimate-VAPT-Scanner.git
   cd Ultimate-VAPT-Scanner
   ```

2. **Build and run the container**:
   Ensure Docker and Docker Compose are installed, then run:
   ```bash
   docker-compose up --build
   ```

3. **Access the Web UI**:
   Once the container is running, open your web browser and navigate to:
   👉 **`http://localhost:5000`**

### Method 2: Manual Installation (Kali Linux / Ubuntu)

If you prefer to run the script directly on your host machine, you must install all underlying security tools manually.

1. **Install System Dependencies**:
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip nmap gobuster nuclei sqlmap hydra wafw00f proxychains4 wkhtmltopdf chromium
   ```

2. **Install Python Requirements**:
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Run the Application**:
   ```bash
   python3 app.py
   ```

4. **Access the Web UI**:
   Navigate to **`http://localhost:5000`** in your browser.

---

## 📖 How to Use

1. **Launch the Interface**: Open `http://localhost:5000` in your web browser.
2. **Enter Target**: In the target field, enter the domain or IP address you wish to scan (e.g., `example.com` or `http://target.local`).
3. **Select Modules**: Check the boxes for the specific tools you want to run (e.g., Nmap, Gobuster, SQLMap).
4. **Enable Anonymity (Optional)**: Check the "Anonymous Mode" toggle to route your scan through Tor (Requires Tor to be active on the host/container).
5. **Start Scan**: Click the "Start Scan" button.
6. **Monitor Live Progress**: Watch the live terminal feed on the web interface. As vulnerabilities or paths are discovered, they will stream directly to your screen.
7. **Download Report**: Once the scan finishes, a "Download PDF Report" button will appear. Click it to receive a detailed breakdown of the findings, AI summary, and visual proof-of-concepts.

---

## ⚠️ Disclaimer

**Educational and Authorized Use Only!**  
This tool was created for educational purposes, ethical hacking, and authorized penetration testing. You must have explicit, written permission from the system owner before running this tool against any infrastructure. The developers and contributors are not responsible for any misuse, damage, or illegal activities caused by the use of this software.
