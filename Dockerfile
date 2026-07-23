FROM python:3.12-slim-bookworm

LABEL maintainer="NullScan SecurityPlatform"

# Install system-level hacking tools & anonymity stack
# Note: Nikto requires Perl. We clone Nikto from GitHub since it's not in the default bookworm repo.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whois \
    dnsutils \
    gobuster \
    dirb \
    curl \
    wget \
    tor \
    proxychains4 \
    unzip \
    wget \
    curl \
    git \
    sqlmap \
    hydra \
    chromium \
    chromium-driver \
    wkhtmltopdf \
    && rm -rf /var/lib/apt/lists/*

# Install modern Go-based tools (Nuclei, Subfinder, Httpx)
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/nuclei_3.2.9_linux_amd64.zip && \
    unzip -o nuclei_3.2.9_linux_amd64.zip && mv nuclei /usr/local/bin/ && rm nuclei* && \
    wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && \
    unzip -o subfinder_2.6.6_linux_amd64.zip && mv subfinder /usr/local/bin/ && rm subfinder* && \
    wget https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip && \
    unzip -o httpx_1.6.0_linux_amd64.zip && mv httpx /usr/local/bin/ && rm httpx*

# Configure Proxychains to use Tor (default is SOCKS4 127.0.0.1 9050, 
# but proxychains4 in bookworm already defaults to this)
RUN sed -i 's/socks4 \t127.0.0.1 9050/socks5 127.0.0.1 9050/' /etc/proxychains4.conf

# Configure Tor Control Port for IP Rotation
RUN echo "ControlPort 9051" >> /etc/tor/torrc && \
    echo 'HashedControlPassword 16:B5205B17CB095EC36023281E5F17E17034E28104683D934F6CCDC03E9A' >> /etc/tor/torrc

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Set up entrypoint
RUN chmod +x entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["/app/entrypoint.sh"]
