"""Demo/mock data seeder for Arcanum Core.

Seeds realistic security assessment data so the platform is functional
out of the box without needing Ollama or real targets.
"""

import json
import uuid
from datetime import datetime, timezone, timedelta

from .database import Database
from .cve_kb import CVEKnowledgeBase, CVEEntry


def _now_iso(offset_hours: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=offset_hours)).isoformat()


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Demo sessions
# ---------------------------------------------------------------------------

DEMO_SESSIONS = [
    {
        "id": "op-demo-recon01",
        "name": "demo-full-recon",
        "target": "example.com",
        "mode": "autopilot",
        "status": "complete",
        "scope": json.dumps({"include": ["*.example.com"], "exclude": ["internal.example.com"]}),
        "progress": json.dumps({"phase": "REPORT", "percent": 100.0, "current_task": "Complete"}),
        "assets": json.dumps({
            "hosts": ["example.com", "api.example.com", "staging.example.com", "mail.example.com"],
            "ports": ["80", "443", "8080", "22", "3306"],
            "services": ["nginx/1.24", "OpenSSH 8.9", "MySQL 8.0"],
            "urls": ["https://example.com", "https://api.example.com/v1", "https://staging.example.com"],
        }),
        "findings_count": 7,
    },
    {
        "id": "op-demo-webapp01",
        "name": "demo-web-assessment",
        "target": "testapp.local",
        "mode": "copilot",
        "status": "running",
        "scope": json.dumps({"include": ["testapp.local"], "exclude": []}),
        "progress": json.dumps({"phase": "EXPLOIT", "percent": 65.0, "current_task": "Testing SQL injection vectors"}),
        "assets": json.dumps({
            "hosts": ["testapp.local"],
            "ports": ["80", "443", "8443"],
            "services": ["Apache/2.4.58", "PHP/8.2", "MariaDB 10.11"],
            "urls": ["https://testapp.local", "https://testapp.local/api/v2", "https://testapp.local/admin"],
        }),
        "findings_count": 4,
    },
    {
        "id": "op-demo-network01",
        "name": "demo-network-pentest",
        "target": "10.0.0.0/24",
        "mode": "manual",
        "status": "paused",
        "scope": json.dumps({"include": ["10.0.0.0/24"], "exclude": ["10.0.0.1"]}),
        "progress": json.dumps({"phase": "ANALYSIS", "percent": 40.0, "current_task": "Paused - awaiting approval"}),
        "assets": json.dumps({
            "hosts": ["10.0.0.5", "10.0.0.10", "10.0.0.15", "10.0.0.20", "10.0.0.50"],
            "ports": ["22", "80", "445", "3389", "5432"],
            "services": ["OpenSSH 9.0", "IIS/10.0", "PostgreSQL 15", "SMBv3"],
            "urls": [],
        }),
        "findings_count": 2,
    },
]

# ---------------------------------------------------------------------------
# Demo findings
# ---------------------------------------------------------------------------

DEMO_FINDINGS = [
    # Session 1: demo-full-recon
    {
        "id": "finding-crit001",
        "session_id": "op-demo-recon01",
        "title": "SQL Injection in /api/v1/users endpoint",
        "type": "sqli",
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected": json.dumps({"url": "https://api.example.com/v1/users", "method": "POST", "parameter": "user_id"}),
        "evidence": json.dumps({
            "request": "POST /api/v1/users HTTP/1.1\\nHost: api.example.com\\nContent-Type: application/json\\n\\n{\"user_id\": \"1' OR '1'='1\"}",
            "response": "HTTP/1.1 200 OK\\n\\n[{\"id\":1,\"username\":\"admin\"},{\"id\":2,\"username\":\"user1\"}...]",
        }),
        "poc": json.dumps({"command": "sqlmap -u 'https://api.example.com/v1/users' --data='user_id=1' --dbs"}),
        "cve_id": None,
        "cwe_ids": json.dumps(["CWE-89"]),
        "remediation": "Use parameterized queries. Implement input validation. Deploy WAF rules.",
        "verified": True,
    },
    {
        "id": "finding-crit002",
        "session_id": "op-demo-recon01",
        "title": "Remote Code Execution via CVE-2024-4577 (PHP CGI)",
        "type": "rce",
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected": json.dumps({"url": "https://staging.example.com/", "method": "GET", "parameter": "php-cgi"}),
        "evidence": json.dumps({
            "request": "GET /?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1",
            "response": "uid=33(www-data) gid=33(www-data)",
        }),
        "poc": json.dumps({"command": "curl -s 'https://staging.example.com/?%ADd+allow_url_include%3d1' --data '<?php system(\"id\"); ?>'"}),
        "cve_id": "CVE-2024-4577",
        "cwe_ids": json.dumps(["CWE-78"]),
        "remediation": "Update PHP to latest version. Disable PHP-CGI if not needed. Apply vendor patch.",
        "verified": True,
    },
    {
        "id": "finding-high001",
        "session_id": "op-demo-recon01",
        "title": "Cross-Site Scripting (Stored XSS) in comment field",
        "type": "xss",
        "severity": "high",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N",
        "affected": json.dumps({"url": "https://example.com/blog/post/42/comment", "method": "POST", "parameter": "body"}),
        "evidence": json.dumps({
            "request": "POST /blog/post/42/comment HTTP/1.1\\n\\nbody=<script>alert(document.cookie)</script>",
            "response": "HTTP/1.1 200 OK\\n\\n...stored and rendered...",
        }),
        "poc": json.dumps({"command": "dalfox url 'https://example.com/blog/post/42/comment' -b body"}),
        "cve_id": None,
        "cwe_ids": json.dumps(["CWE-79"]),
        "remediation": "Implement output encoding. Use Content-Security-Policy header. Sanitize input.",
        "verified": True,
    },
    {
        "id": "finding-high002",
        "session_id": "op-demo-recon01",
        "title": "Exposed MySQL on public interface (port 3306)",
        "type": "misconfiguration",
        "severity": "high",
        "cvss_score": 7.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "affected": json.dumps({"url": "example.com:3306", "method": "TCP"}),
        "evidence": json.dumps({"request": "nmap -sV -p3306 example.com", "response": "3306/tcp open mysql MySQL 8.0.35"}),
        "poc": json.dumps({"command": "nmap -sV -p3306 --script mysql-info example.com"}),
        "cve_id": None,
        "cwe_ids": json.dumps(["CWE-200"]),
        "remediation": "Restrict MySQL to localhost or private network. Use firewall rules. Enforce strong auth.",
        "verified": True,
    },
    {
        "id": "finding-med001",
        "session_id": "op-demo-recon01",
        "title": "Missing security headers (CSP, X-Frame-Options)",
        "type": "misconfiguration",
        "severity": "medium",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "affected": json.dumps({"url": "https://example.com", "method": "GET"}),
        "evidence": json.dumps({"request": "curl -I https://example.com", "response": "Missing: CSP, X-Frame-Options, X-Content-Type-Options"}),
        "poc": None,
        "cve_id": None,
        "cwe_ids": json.dumps(["CWE-693"]),
        "remediation": "Add Content-Security-Policy, X-Frame-Options: DENY, X-Content-Type-Options: nosniff headers.",
        "verified": False,
    },
    {
        "id": "finding-med002",
        "session_id": "op-demo-recon01",
        "title": "Directory listing enabled on /assets/",
        "type": "information_disclosure",
        "severity": "medium",
        "cvss_score": 5.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "affected": json.dumps({"url": "https://staging.example.com/assets/", "method": "GET"}),
        "evidence": json.dumps({"request": "GET /assets/ HTTP/1.1", "response": "Index of /assets/ ... backup.sql, config.ini"}),
        "poc": None,
        "cve_id": None,
        "cwe_ids": json.dumps(["CWE-548"]),
        "remediation": "Disable directory listing in web server config. Remove sensitive files from public directories.",
        "verified": True,
    },
    {
        "id": "finding-low001",
        "session_id": "op-demo-recon01",
        "title": "Server version disclosure in HTTP headers",
        "type": "information_disclosure",
        "severity": "low",
        "cvss_score": 3.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "affected": json.dumps({"url": "https://example.com", "method": "HEAD"}),
        "evidence": json.dumps({"request": "HEAD / HTTP/1.1", "response": "Server: nginx/1.24.0"}),
        "poc": None,
        "cve_id": None,
        "cwe_ids": json.dumps(["CWE-200"]),
        "remediation": "Remove or obscure the Server header. Use server_tokens off in nginx config.",
        "verified": False,
    },

    # Session 2: demo-web-assessment
    {
        "id": "finding-crit003",
        "session_id": "op-demo-webapp01",
        "title": "Authentication bypass via JWT none algorithm",
        "type": "auth_bypass",
        "severity": "critical",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "affected": json.dumps({"url": "https://testapp.local/api/v2/admin", "method": "GET", "parameter": "Authorization"}),
        "evidence": json.dumps({
            "request": "GET /api/v2/admin HTTP/1.1\\nAuthorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0...",
            "response": "HTTP/1.1 200 OK\\n\\n{\"admin\": true, \"users\": [...]}",
        }),
        "poc": json.dumps({"command": "python3 jwt_tool.py <token> -X a"}),
        "cve_id": None,
        "cwe_ids": json.dumps(["CWE-287", "CWE-345"]),
        "remediation": "Enforce algorithm validation in JWT library. Reject 'none' algorithm. Use RS256.",
        "verified": True,
    },
    {
        "id": "finding-high003",
        "session_id": "op-demo-webapp01",
        "title": "SSRF via URL parameter in /api/v2/fetch",
        "type": "ssrf",
        "severity": "high",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "affected": json.dumps({"url": "https://testapp.local/api/v2/fetch", "method": "POST", "parameter": "url"}),
        "evidence": json.dumps({
            "request": "POST /api/v2/fetch HTTP/1.1\\n\\n{\"url\": \"http://169.254.169.254/latest/meta-data/\"}",
            "response": "ami-id\\nami-launch-index\\nhostname\\ninstance-id",
        }),
        "poc": json.dumps({"command": "curl -X POST https://testapp.local/api/v2/fetch -d '{\"url\":\"http://169.254.169.254/latest/meta-data/\"}'"}),
        "cve_id": None,
        "cwe_ids": json.dumps(["CWE-918"]),
        "remediation": "Implement URL allowlist. Block internal IP ranges. Use network-level controls.",
        "verified": True,
    },
    {
        "id": "finding-med003",
        "session_id": "op-demo-webapp01",
        "title": "CORS misconfiguration allows arbitrary origins",
        "type": "misconfiguration",
        "severity": "medium",
        "cvss_score": 5.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "affected": json.dumps({"url": "https://testapp.local/api/v2/", "method": "OPTIONS"}),
        "evidence": json.dumps({
            "request": "OPTIONS /api/v2/ HTTP/1.1\\nOrigin: https://evil.com",
            "response": "Access-Control-Allow-Origin: https://evil.com\\nAccess-Control-Allow-Credentials: true",
        }),
        "poc": None,
        "cve_id": None,
        "cwe_ids": json.dumps(["CWE-942"]),
        "remediation": "Restrict CORS to trusted origins. Remove wildcard and credential reflection.",
        "verified": True,
    },
    {
        "id": "finding-low002",
        "session_id": "op-demo-webapp01",
        "title": "Cookie missing Secure and HttpOnly flags",
        "type": "misconfiguration",
        "severity": "low",
        "cvss_score": 3.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "affected": json.dumps({"url": "https://testapp.local/login", "method": "POST"}),
        "evidence": json.dumps({"request": "POST /login", "response": "Set-Cookie: session=abc123; Path=/"}),
        "poc": None,
        "cve_id": None,
        "cwe_ids": json.dumps(["CWE-614"]),
        "remediation": "Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies.",
        "verified": False,
    },

    # Session 3: demo-network-pentest
    {
        "id": "finding-high004",
        "session_id": "op-demo-network01",
        "title": "SMB signing disabled on domain controller",
        "type": "misconfiguration",
        "severity": "high",
        "cvss_score": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "affected": json.dumps({"url": "10.0.0.10:445", "method": "SMB"}),
        "evidence": json.dumps({"request": "netexec smb 10.0.0.10", "response": "SMBv3 signing:False name:DC01 domain:corp.local"}),
        "poc": json.dumps({"command": "netexec smb 10.0.0.10 --gen-relay-list targets.txt"}),
        "cve_id": None,
        "cwe_ids": json.dumps(["CWE-311"]),
        "remediation": "Enable SMB signing via GPO: RequireSecuritySignature=1. Apply to all domain controllers.",
        "verified": True,
    },
    {
        "id": "finding-med004",
        "session_id": "op-demo-network01",
        "title": "SNMP community string 'public' accepted",
        "type": "weak_credentials",
        "severity": "medium",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "affected": json.dumps({"url": "10.0.0.50:161", "method": "UDP"}),
        "evidence": json.dumps({"request": "snmpwalk -v2c -c public 10.0.0.50", "response": "SNMPv2-MIB::sysDescr.0 = STRING: Linux router 5.15.0"}),
        "poc": json.dumps({"command": "snmpwalk -v2c -c public 10.0.0.50 1.3.6.1.2.1"}),
        "cve_id": None,
        "cwe_ids": json.dumps(["CWE-521"]),
        "remediation": "Change default SNMP community strings. Migrate to SNMPv3 with authentication.",
        "verified": True,
    },
]

# ---------------------------------------------------------------------------
# Demo stash items
# ---------------------------------------------------------------------------

DEMO_STASH = [
    {"id": "stash-demo0001", "type": "credential", "value": "admin:P@ssw0rd123!", "note": "Default admin creds on staging", "session_id": "op-demo-recon01"},
    {"id": "stash-demo0002", "type": "host", "value": "api.example.com", "note": "Primary API endpoint", "session_id": "op-demo-recon01"},
    {"id": "stash-demo0003", "type": "host", "value": "staging.example.com", "note": "Staging - vulnerable to CVE-2024-4577", "session_id": "op-demo-recon01"},
    {"id": "stash-demo0004", "type": "token", "value": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZX0.", "note": "Forged JWT with none alg", "session_id": "op-demo-webapp01"},
    {"id": "stash-demo0005", "type": "hash", "value": "$2b$12$LJ3m4ys3Ym5G...truncated", "note": "Admin password hash from DB dump", "session_id": "op-demo-recon01"},
    {"id": "stash-demo0006", "type": "payload", "value": "' OR '1'='1' -- -", "note": "SQLi payload that worked on /api/v1/users", "session_id": "op-demo-recon01"},
    {"id": "stash-demo0007", "type": "host", "value": "10.0.0.10", "note": "DC01 - SMB signing disabled", "session_id": "op-demo-network01"},
]

# ---------------------------------------------------------------------------
# Demo CVEs
# ---------------------------------------------------------------------------

DEMO_CVES = [
    CVEEntry(id="CVE-2024-4577", description="PHP CGI argument injection vulnerability allows remote attackers to execute arbitrary commands via crafted HTTP requests when PHP is configured with certain CGI configurations.", cvss_score=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwe_ids=["CWE-78"], affected_products=["PHP <8.1.29", "PHP <8.2.20", "PHP <8.3.8"], exploit_available=True, published_at="2024-06-09"),
    CVEEntry(id="CVE-2024-3400", description="Command injection vulnerability in Palo Alto Networks PAN-OS GlobalProtect gateway enables unauthenticated attacker to execute arbitrary code with root privileges.", cvss_score=10.0, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cwe_ids=["CWE-77"], affected_products=["PAN-OS 10.2", "PAN-OS 11.0", "PAN-OS 11.1"], exploit_available=True, published_at="2024-04-12"),
    CVEEntry(id="CVE-2024-21887", description="Command injection vulnerability in Ivanti Connect Secure and Policy Secure web components allows authenticated administrator to send specially crafted requests and execute arbitrary commands.", cvss_score=9.1, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", cwe_ids=["CWE-77"], affected_products=["Ivanti Connect Secure", "Ivanti Policy Secure"], exploit_available=True, published_at="2024-01-10"),
    CVEEntry(id="CVE-2023-44228", description="Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other endpoints. Allows remote code execution via crafted log messages.", cvss_score=10.0, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cwe_ids=["CWE-502", "CWE-400"], affected_products=["Apache Log4j2 <2.17.1"], exploit_available=True, published_at="2021-12-10"),
    CVEEntry(id="CVE-2024-27198", description="Authentication bypass vulnerability in JetBrains TeamCity allows unauthenticated attacker to gain administrative access to the server.", cvss_score=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwe_ids=["CWE-288"], affected_products=["JetBrains TeamCity <2023.11.4"], exploit_available=True, published_at="2024-03-04"),
    CVEEntry(id="CVE-2024-0012", description="Authentication bypass in Palo Alto Networks PAN-OS management web interface allows unauthenticated attacker with network access to gain PAN-OS administrator privileges.", cvss_score=9.3, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwe_ids=["CWE-306"], affected_products=["PAN-OS 10.2", "PAN-OS 11.0", "PAN-OS 11.1", "PAN-OS 11.2"], exploit_available=True, published_at="2024-11-18"),
    CVEEntry(id="CVE-2023-46805", description="Authentication bypass vulnerability in Ivanti Connect Secure allows remote attacker to access restricted resources by bypassing control checks.", cvss_score=8.2, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", cwe_ids=["CWE-287"], affected_products=["Ivanti Connect Secure 9.x", "Ivanti Connect Secure 22.x"], exploit_available=True, published_at="2024-01-10"),
    CVEEntry(id="CVE-2024-23897", description="Jenkins CLI arbitrary file read vulnerability allows attackers to read files from the Jenkins controller file system using the args4j parser.", cvss_score=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwe_ids=["CWE-22"], affected_products=["Jenkins <2.442", "Jenkins LTS <2.426.3"], exploit_available=True, published_at="2024-01-24"),
    CVEEntry(id="CVE-2024-6387", description="Race condition in OpenSSH server (sshd) signal handler allows unauthenticated remote code execution as root on glibc-based Linux systems.", cvss_score=8.1, cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", cwe_ids=["CWE-362"], affected_products=["OpenSSH 8.5p1-9.7p1"], exploit_available=True, published_at="2024-07-01"),
    CVEEntry(id="CVE-2024-47575", description="Missing authentication for critical function in FortiManager allows remote unauthenticated attacker to execute arbitrary code via specially crafted requests.", cvss_score=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwe_ids=["CWE-306"], affected_products=["FortiManager 7.0-7.4", "FortiManager 6.4"], exploit_available=True, published_at="2024-10-23"),
    CVEEntry(id="CVE-2024-1709", description="Authentication bypass using an alternate path in ConnectWise ScreenConnect allows unauthenticated attacker to gain access to confidential data or critical systems.", cvss_score=10.0, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cwe_ids=["CWE-288"], affected_products=["ConnectWise ScreenConnect <23.9.8"], exploit_available=True, published_at="2024-02-19"),
    CVEEntry(id="CVE-2023-34362", description="SQL injection vulnerability in MOVEit Transfer allows unauthenticated attacker to access the database. Actively exploited by Clop ransomware group.", cvss_score=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwe_ids=["CWE-89"], affected_products=["MOVEit Transfer <2023.0.1"], exploit_available=True, published_at="2023-06-02"),
]


async def seed_demo_sessions(db: Database) -> int:
    """Seed demo sessions and findings. Returns count of sessions created."""
    existing = await db.fetch_all("SELECT id FROM sessions WHERE id LIKE 'op-demo-%'")
    if existing:
        return 0  # Already seeded

    now = _now_iso()
    for s in DEMO_SESSIONS:
        await db.execute(
            """INSERT OR IGNORE INTO sessions
               (id, name, target, mode, status, scope, progress, assets, findings_count, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (s["id"], s["name"], s["target"], s["mode"], s["status"],
             s["scope"], s["progress"], s["assets"], s["findings_count"],
             _now_iso(48), now),
        )

    for f in DEMO_FINDINGS:
        await db.execute(
            """INSERT OR IGNORE INTO findings
               (id, session_id, title, type, severity, cvss_score, cvss_vector,
                affected, evidence, poc, cve_id, cwe_ids, remediation, verified, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (f["id"], f["session_id"], f["title"], f["type"], f["severity"],
             f["cvss_score"], f["cvss_vector"], f["affected"], f["evidence"],
             f["poc"], f["cve_id"], f["cwe_ids"], f["remediation"],
             f["verified"], _now_iso(24)),
        )

    for s in DEMO_STASH:
        await db.execute(
            """INSERT OR IGNORE INTO stash (id, type, value, note, session_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (s["id"], s["type"], s["value"], s["note"], s["session_id"], _now_iso(36)),
        )

    return len(DEMO_SESSIONS)


async def seed_demo_cves(cve_kb: CVEKnowledgeBase) -> int:
    """Seed demo CVEs. Returns count of CVEs added."""
    existing = await cve_kb.count()
    if existing > 0:
        return 0
    await cve_kb.bulk_import(DEMO_CVES)
    return len(DEMO_CVES)


async def seed_all_demo_data(db: Database, cve_kb: CVEKnowledgeBase) -> dict:
    """Seed all demo data. Returns summary of what was seeded."""
    sessions_count = await seed_demo_sessions(db)
    cves_count = await seed_demo_cves(cve_kb)
    return {
        "sessions": sessions_count,
        "findings": len(DEMO_FINDINGS) if sessions_count > 0 else 0,
        "stash_items": len(DEMO_STASH) if sessions_count > 0 else 0,
        "cves": cves_count,
    }
