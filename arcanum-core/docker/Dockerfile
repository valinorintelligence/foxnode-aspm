FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

# Install base system tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    curl wget git jq unzip \
    # Recon tools
    subfinder dnsx nmap masscan httpx-toolkit katana theharvester \
    # Web tools
    nuclei sqlmap feroxbuster ffuf arjun wpscan \
    # Network tools
    crackmapexec snmp tshark chisel \
    # Creds tools
    hashcat hydra \
    # Exploit tools
    metasploit-framework \
    # Post-exploit
    impacket-scripts \
    # OSINT
    exiftool \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Python-based tools
RUN pip3 install --break-system-packages --no-cache-dir \
    sherlock-project holehe trufflehog gowitness \
    pwncat-cs pwntools jwt-tool

# Install SecLists wordlists
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/seclists

# Create workspace
RUN mkdir -p /workspace && chown nobody:nogroup /workspace
WORKDIR /workspace

USER nobody
CMD ["/bin/bash"]
