"""
AI Remediation Copilot Service
===============================
Rule-based + template engine that generates LLM-quality remediation advice
for security findings. Maps CWE IDs to detailed remediation templates with
language-aware code examples.
"""

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app.models.finding import Finding, FindingSeverity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Language detection from file paths
# ---------------------------------------------------------------------------

LANG_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".java": "java",
    ".go": "golang",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".cpp": "cpp",
    ".rs": "rust",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".sh": "shell",
    ".sql": "sql",
    ".xml": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".html": "html",
    ".htm": "html",
    ".tf": "terraform",
    ".dockerfile": "dockerfile",
}


def _detect_language(file_path: Optional[str]) -> str:
    """Detect programming language from file extension."""
    if not file_path:
        return "python"
    ext = os.path.splitext(file_path)[1].lower()
    return LANG_MAP.get(ext, "python")


# ---------------------------------------------------------------------------
# Effort estimation by severity
# ---------------------------------------------------------------------------

EFFORT_BY_SEVERITY: dict[str, dict] = {
    "critical": {"min_hours": 4, "max_hours": 16, "label": "High"},
    "high": {"min_hours": 2, "max_hours": 8, "label": "Medium-High"},
    "medium": {"min_hours": 1, "max_hours": 4, "label": "Medium"},
    "low": {"min_hours": 0.5, "max_hours": 2, "label": "Low"},
    "info": {"min_hours": 0.25, "max_hours": 1, "label": "Minimal"},
}


# ---------------------------------------------------------------------------
# CWE Remediation Templates
# ---------------------------------------------------------------------------

@dataclass
class CWETemplate:
    cwe_id: int
    name: str
    risk_explanation: str
    impact_analysis: str
    remediation_steps: list[str]
    code_examples: dict[str, dict[str, str]]  # lang -> {vulnerable, fixed}
    references: list[str]
    priority_reasoning: str
    owasp_category: str = ""
    estimated_effort_hours: float = 4.0


# Master template registry keyed by CWE ID
CWE_TEMPLATES: dict[int, CWETemplate] = {}


def _register(t: CWETemplate) -> None:
    CWE_TEMPLATES[t.cwe_id] = t


# ---- CWE-89: SQL Injection ----
_register(CWETemplate(
    cwe_id=89,
    name="SQL Injection",
    risk_explanation=(
        "SQL Injection occurs when untrusted data is sent to an interpreter as "
        "part of a command or query. An attacker can craft hostile input to "
        "access, modify, or delete data, bypass authentication, and in some "
        "cases execute operating-system commands."
    ),
    impact_analysis=(
        "Full database compromise, unauthorized data access, data loss, "
        "authentication bypass, and potential remote code execution. "
        "This is consistently ranked as one of the most critical web "
        "application vulnerabilities."
    ),
    remediation_steps=[
        "Use parameterized queries (prepared statements) for all database access.",
        "Use an ORM that handles query parameterization automatically.",
        "Apply input validation with strict allow-lists for expected data formats.",
        "Escape special characters if parameterized queries are not possible.",
        "Apply the principle of least privilege to database accounts.",
        "Deploy a Web Application Firewall (WAF) as an additional defense layer.",
        "Implement query logging and anomaly detection to catch injection attempts.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: String concatenation in SQL\n"
                "query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
                "cursor.execute(query)"
            ),
            "fixed": (
                "# FIXED: Parameterized query\n"
                "query = \"SELECT * FROM users WHERE username = %s\"\n"
                "cursor.execute(query, (username,))\n"
                "\n"
                "# Or with SQLAlchemy ORM:\n"
                "user = session.query(User).filter(User.username == username).first()"
            ),
        },
        "javascript": {
            "vulnerable": (
                "// VULNERABLE: String interpolation in SQL\n"
                "const query = `SELECT * FROM users WHERE username = '${username}'`;\n"
                "db.query(query);"
            ),
            "fixed": (
                "// FIXED: Parameterized query\n"
                "const query = 'SELECT * FROM users WHERE username = $1';\n"
                "db.query(query, [username]);"
            ),
        },
        "java": {
            "vulnerable": (
                "// VULNERABLE: String concatenation\n"
                "String query = \"SELECT * FROM users WHERE username = '\" + username + \"'\";\n"
                "Statement stmt = conn.createStatement();\n"
                "ResultSet rs = stmt.executeQuery(query);"
            ),
            "fixed": (
                "// FIXED: PreparedStatement\n"
                "String query = \"SELECT * FROM users WHERE username = ?\";\n"
                "PreparedStatement pstmt = conn.prepareStatement(query);\n"
                "pstmt.setString(1, username);\n"
                "ResultSet rs = pstmt.executeQuery();"
            ),
        },
        "golang": {
            "vulnerable": (
                "// VULNERABLE: String formatting in SQL\n"
                "query := fmt.Sprintf(\"SELECT * FROM users WHERE username = '%s'\", username)\n"
                "rows, err := db.Query(query)"
            ),
            "fixed": (
                "// FIXED: Parameterized query\n"
                "rows, err := db.Query(\"SELECT * FROM users WHERE username = $1\", username)"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "SQL Injection is a critical vulnerability that can lead to complete "
        "database compromise. Remediation should be treated as an immediate priority."
    ),
    owasp_category="A03:2021 - Injection",
    estimated_effort_hours=4.0,
))

# ---- CWE-79: Cross-Site Scripting (XSS) ----
_register(CWETemplate(
    cwe_id=79,
    name="Cross-Site Scripting (XSS)",
    risk_explanation=(
        "XSS vulnerabilities allow attackers to inject client-side scripts into "
        "web pages viewed by other users. This can result in session hijacking, "
        "credential theft, defacement, and malware distribution."
    ),
    impact_analysis=(
        "Session hijacking, cookie theft, keylogging, phishing attacks, "
        "credential harvesting, and unauthorized actions on behalf of users. "
        "Stored XSS can affect all users who visit the compromised page."
    ),
    remediation_steps=[
        "Encode all untrusted output using context-appropriate encoding (HTML, JS, URL, CSS).",
        "Use a Content Security Policy (CSP) header to restrict script execution.",
        "Use modern frameworks that auto-escape output by default (React, Angular, Vue).",
        "Sanitize HTML input using a well-tested library (DOMPurify, Bleach).",
        "Set HttpOnly and Secure flags on session cookies.",
        "Validate input on the server side with strict allow-lists.",
        "Implement Subresource Integrity (SRI) for external scripts.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: Direct insertion of user input into HTML\n"
                "return f\"<div>Welcome, {user_input}</div>\""
            ),
            "fixed": (
                "# FIXED: Use markupsafe for escaping\n"
                "from markupsafe import escape\n"
                "return f\"<div>Welcome, {escape(user_input)}</div>\"\n"
                "\n"
                "# Or use a template engine (Jinja2 auto-escapes):\n"
                "return render_template('welcome.html', name=user_input)"
            ),
        },
        "javascript": {
            "vulnerable": (
                "// VULNERABLE: innerHTML with user input\n"
                "element.innerHTML = '<div>Welcome, ' + userInput + '</div>';"
            ),
            "fixed": (
                "// FIXED: Use textContent for plain text\n"
                "element.textContent = 'Welcome, ' + userInput;\n"
                "\n"
                "// Or use DOMPurify for HTML content:\n"
                "element.innerHTML = DOMPurify.sanitize(userInput);"
            ),
        },
        "java": {
            "vulnerable": (
                "// VULNERABLE: Unescaped output\n"
                "out.println(\"<div>Welcome, \" + userInput + \"</div>\");"
            ),
            "fixed": (
                "// FIXED: Use OWASP encoder\n"
                "import org.owasp.encoder.Encode;\n"
                "out.println(\"<div>Welcome, \" + Encode.forHtml(userInput) + \"</div>\");"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://cwe.mitre.org/data/definitions/79.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "XSS is a high-impact vulnerability especially when stored. It should be "
        "remediated promptly to protect user sessions and sensitive data."
    ),
    owasp_category="A03:2021 - Injection",
    estimated_effort_hours=3.0,
))

# ---- CWE-22: Path Traversal ----
_register(CWETemplate(
    cwe_id=22,
    name="Path Traversal",
    risk_explanation=(
        "Path Traversal allows attackers to access files and directories outside "
        "the intended directory by manipulating file paths with sequences like "
        "'../'. This can expose sensitive system files, configuration data, "
        "and source code."
    ),
    impact_analysis=(
        "Unauthorized read access to sensitive files (/etc/passwd, config files, "
        "application source), potential write access leading to code execution, "
        "and information disclosure that aids further attacks."
    ),
    remediation_steps=[
        "Validate and canonicalize all file paths before use.",
        "Use a whitelist of allowed file names or paths.",
        "Implement a chroot jail or sandbox for file operations.",
        "Strip or reject path traversal sequences (../, ..\\ , %2e%2e).",
        "Use framework-provided safe file-serving methods.",
        "Enforce strict directory boundaries using realpath() checks.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: Direct path concatenation\n"
                "file_path = os.path.join(UPLOAD_DIR, user_filename)\n"
                "return open(file_path).read()"
            ),
            "fixed": (
                "# FIXED: Validate resolved path stays within allowed directory\n"
                "base = os.path.realpath(UPLOAD_DIR)\n"
                "requested = os.path.realpath(os.path.join(UPLOAD_DIR, user_filename))\n"
                "if not requested.startswith(base + os.sep):\n"
                "    raise ValueError('Invalid file path')\n"
                "return open(requested).read()"
            ),
        },
        "javascript": {
            "vulnerable": (
                "// VULNERABLE: Unvalidated path join\n"
                "const filePath = path.join(uploadDir, userFilename);\n"
                "fs.readFile(filePath, callback);"
            ),
            "fixed": (
                "// FIXED: Resolve and verify path prefix\n"
                "const base = path.resolve(uploadDir);\n"
                "const requested = path.resolve(path.join(uploadDir, userFilename));\n"
                "if (!requested.startsWith(base + path.sep)) {\n"
                "  throw new Error('Invalid file path');\n"
                "}\n"
                "fs.readFile(requested, callback);"
            ),
        },
        "java": {
            "vulnerable": (
                "// VULNERABLE: Direct concatenation\n"
                "File file = new File(uploadDir + \"/\" + userFilename);"
            ),
            "fixed": (
                "// FIXED: Canonical path check\n"
                "File base = new File(uploadDir).getCanonicalFile();\n"
                "File requested = new File(base, userFilename).getCanonicalFile();\n"
                "if (!requested.toPath().startsWith(base.toPath())) {\n"
                "    throw new SecurityException(\"Path traversal detected\");\n"
                "}"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "https://cwe.mitre.org/data/definitions/22.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "Path traversal can expose sensitive server-side files and configuration. "
        "Priority depends on whether the application handles file-based operations "
        "on user-controlled paths."
    ),
    owasp_category="A01:2021 - Broken Access Control",
    estimated_effort_hours=3.0,
))

# ---- CWE-78: OS Command Injection ----
_register(CWETemplate(
    cwe_id=78,
    name="OS Command Injection",
    risk_explanation=(
        "Command Injection occurs when an application passes unsafe user data "
        "to a system shell. An attacker can execute arbitrary operating system "
        "commands with the privileges of the vulnerable application."
    ),
    impact_analysis=(
        "Full server compromise, arbitrary command execution, data exfiltration, "
        "lateral movement within the network, installation of backdoors, and "
        "complete loss of confidentiality, integrity, and availability."
    ),
    remediation_steps=[
        "Avoid calling OS commands from application code whenever possible.",
        "Use language-native APIs instead of shell commands (e.g., shutil instead of cp).",
        "If OS commands are unavoidable, use parameterized interfaces (subprocess with list args).",
        "Never pass user input directly to shell=True or equivalent.",
        "Validate and sanitize input with strict allow-lists.",
        "Apply the principle of least privilege for the application process.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: Shell injection via string formatting\n"
                "os.system(f'ping -c 4 {host}')\n"
                "# or\n"
                "subprocess.call(f'nslookup {domain}', shell=True)"
            ),
            "fixed": (
                "# FIXED: Use subprocess with list args, no shell\n"
                "import shlex\n"
                "subprocess.run(['ping', '-c', '4', host], shell=False, check=True)\n"
                "\n"
                "# Better: use native Python libraries\n"
                "import socket\n"
                "result = socket.getaddrinfo(domain, None)"
            ),
        },
        "javascript": {
            "vulnerable": (
                "// VULNERABLE: exec with user input\n"
                "const { exec } = require('child_process');\n"
                "exec(`ping -c 4 ${host}`);"
            ),
            "fixed": (
                "// FIXED: Use execFile with arguments array\n"
                "const { execFile } = require('child_process');\n"
                "execFile('ping', ['-c', '4', host], callback);"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://cwe.mitre.org/data/definitions/78.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "Command Injection is a critical severity vulnerability that can lead to "
        "complete server compromise. It should be treated as the highest priority."
    ),
    owasp_category="A03:2021 - Injection",
    estimated_effort_hours=4.0,
))

# ---- CWE-502: Deserialization of Untrusted Data ----
_register(CWETemplate(
    cwe_id=502,
    name="Deserialization of Untrusted Data",
    risk_explanation=(
        "Insecure deserialization can allow attackers to execute arbitrary code, "
        "manipulate application logic, or perform denial-of-service attacks by "
        "sending crafted serialized objects."
    ),
    impact_analysis=(
        "Remote code execution, privilege escalation, injection attacks, "
        "denial of service, and object manipulation. This vulnerability is "
        "particularly dangerous because exploitation can be fully automated."
    ),
    remediation_steps=[
        "Do not deserialize data from untrusted sources.",
        "Use safe serialization formats like JSON instead of native serialization.",
        "If native deserialization is required, implement integrity checks (HMAC signatures).",
        "Apply strict type constraints during deserialization.",
        "Run deserialization code in a sandboxed, low-privilege environment.",
        "Monitor and log deserialization activity for anomalies.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: pickle with untrusted data\n"
                "import pickle\n"
                "data = pickle.loads(user_supplied_bytes)"
            ),
            "fixed": (
                "# FIXED: Use JSON for untrusted data\n"
                "import json\n"
                "data = json.loads(user_supplied_string)\n"
                "\n"
                "# If pickle is required, restrict allowed classes:\n"
                "import io\n"
                "class SafeUnpickler(pickle.Unpickler):\n"
                "    SAFE_CLASSES = {'collections': {'OrderedDict'}}\n"
                "    def find_class(self, module, name):\n"
                "        if module in self.SAFE_CLASSES and name in self.SAFE_CLASSES[module]:\n"
                "            return super().find_class(module, name)\n"
                "        raise pickle.UnpicklingError(f'Forbidden: {module}.{name}')"
            ),
        },
        "java": {
            "vulnerable": (
                "// VULNERABLE: Direct ObjectInputStream\n"
                "ObjectInputStream ois = new ObjectInputStream(inputStream);\n"
                "Object obj = ois.readObject();"
            ),
            "fixed": (
                "// FIXED: Use ValidatingObjectInputStream with allow-list\n"
                "ValidatingObjectInputStream vois = new ValidatingObjectInputStream(inputStream);\n"
                "vois.accept(SafeClass.class);\n"
                "Object obj = vois.readObject();"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        "https://cwe.mitre.org/data/definitions/502.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "Insecure deserialization can lead to remote code execution and should "
        "be treated as a critical priority when untrusted data is being deserialized."
    ),
    owasp_category="A08:2021 - Software and Data Integrity Failures",
    estimated_effort_hours=6.0,
))

# ---- CWE-918: Server-Side Request Forgery (SSRF) ----
_register(CWETemplate(
    cwe_id=918,
    name="Server-Side Request Forgery (SSRF)",
    risk_explanation=(
        "SSRF allows an attacker to induce the server-side application to make "
        "HTTP requests to an arbitrary domain or internal resource. This can "
        "bypass firewalls, access internal services, and exfiltrate data."
    ),
    impact_analysis=(
        "Access to internal services and metadata endpoints (e.g., cloud instance "
        "metadata at 169.254.169.254), port scanning of internal networks, "
        "bypassing access controls, and potential remote code execution via "
        "internal service exploitation."
    ),
    remediation_steps=[
        "Validate and sanitize all user-supplied URLs.",
        "Use an allow-list of permitted domains and protocols.",
        "Block requests to private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x).",
        "Disable unnecessary URL schemes (file://, gopher://, dict://).",
        "Use a dedicated HTTP client library with SSRF protections.",
        "Implement network segmentation to limit server-side request reach.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: User-controlled URL with no validation\n"
                "import requests\n"
                "response = requests.get(user_provided_url)\n"
                "return response.text"
            ),
            "fixed": (
                "# FIXED: Validate URL against allow-list and block internal IPs\n"
                "from urllib.parse import urlparse\n"
                "import ipaddress\n"
                "import socket\n"
                "\n"
                "ALLOWED_HOSTS = {'api.example.com', 'cdn.example.com'}\n"
                "\n"
                "def safe_fetch(url: str) -> str:\n"
                "    parsed = urlparse(url)\n"
                "    if parsed.scheme not in ('http', 'https'):\n"
                "        raise ValueError('Invalid scheme')\n"
                "    if parsed.hostname not in ALLOWED_HOSTS:\n"
                "        raise ValueError('Host not allowed')\n"
                "    ip = socket.gethostbyname(parsed.hostname)\n"
                "    if ipaddress.ip_address(ip).is_private:\n"
                "        raise ValueError('Internal IPs are blocked')\n"
                "    return requests.get(url, timeout=5).text"
            ),
        },
        "javascript": {
            "vulnerable": (
                "// VULNERABLE: Unvalidated URL fetch\n"
                "const response = await fetch(userUrl);"
            ),
            "fixed": (
                "// FIXED: Validate against allow-list\n"
                "const allowedHosts = new Set(['api.example.com']);\n"
                "const parsed = new URL(userUrl);\n"
                "if (!allowedHosts.has(parsed.hostname)) {\n"
                "  throw new Error('Host not allowed');\n"
                "}\n"
                "const response = await fetch(userUrl);"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        "https://cwe.mitre.org/data/definitions/918.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "SSRF is a high-priority vulnerability especially in cloud environments "
        "where metadata endpoints can leak credentials and secrets."
    ),
    owasp_category="A10:2021 - Server-Side Request Forgery",
    estimated_effort_hours=4.0,
))

# ---- CWE-611: XML External Entities (XXE) ----
_register(CWETemplate(
    cwe_id=611,
    name="XML External Entities (XXE)",
    risk_explanation=(
        "XXE vulnerabilities occur when XML input containing references to "
        "external entities is processed by a weakly configured XML parser. "
        "This can lead to data exfiltration, SSRF, and denial of service."
    ),
    impact_analysis=(
        "Reading sensitive server files, server-side request forgery, "
        "denial of service via recursive entity expansion (Billion Laughs), "
        "and port scanning of internal networks."
    ),
    remediation_steps=[
        "Disable external entity processing in XML parsers.",
        "Disable DTD processing entirely when not needed.",
        "Use less complex data formats like JSON where possible.",
        "Validate, filter, and sanitize XML input.",
        "Keep XML processors and libraries up to date.",
        "Implement server-side input validation with allow-lists.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: Default lxml parser allows external entities\n"
                "from lxml import etree\n"
                "tree = etree.parse(user_uploaded_xml)"
            ),
            "fixed": (
                "# FIXED: Disable external entities and DTDs\n"
                "from lxml import etree\n"
                "parser = etree.XMLParser(\n"
                "    resolve_entities=False,\n"
                "    no_network=True,\n"
                "    dtd_validation=False,\n"
                "    load_dtd=False,\n"
                ")\n"
                "tree = etree.parse(user_uploaded_xml, parser)"
            ),
        },
        "java": {
            "vulnerable": (
                "// VULNERABLE: Default DocumentBuilderFactory\n"
                "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
                "Document doc = dbf.newDocumentBuilder().parse(inputStream);"
            ),
            "fixed": (
                "// FIXED: Disable external entities\n"
                "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
                "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
                "dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n"
                "dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n"
                "Document doc = dbf.newDocumentBuilder().parse(inputStream);"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "https://cwe.mitre.org/data/definitions/611.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "XXE can lead to sensitive file disclosure and SSRF. Priority is high "
        "when the application processes XML from untrusted sources."
    ),
    owasp_category="A05:2021 - Security Misconfiguration",
    estimated_effort_hours=3.0,
))

# ---- CWE-287: Improper Authentication ----
_register(CWETemplate(
    cwe_id=287,
    name="Improper Authentication",
    risk_explanation=(
        "Improper authentication occurs when the application does not correctly "
        "verify user identity, allowing attackers to bypass authentication "
        "mechanisms and gain unauthorized access."
    ),
    impact_analysis=(
        "Unauthorized access to user accounts, administrative functions, "
        "sensitive data, and the ability to impersonate legitimate users. "
        "Can lead to complete system compromise."
    ),
    remediation_steps=[
        "Implement multi-factor authentication (MFA) for sensitive operations.",
        "Use well-tested authentication frameworks and libraries.",
        "Enforce strong password policies and use bcrypt/Argon2 for hashing.",
        "Implement proper session management with secure cookie flags.",
        "Add brute-force protection with rate limiting and account lockout.",
        "Log and monitor authentication events for anomaly detection.",
        "Use constant-time comparison for tokens and credentials.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: Weak password comparison and no rate limiting\n"
                "def login(username, password):\n"
                "    user = db.query(User).filter_by(username=username).first()\n"
                "    if user and user.password == password:  # plain text comparison\n"
                "        return create_session(user)"
            ),
            "fixed": (
                "# FIXED: Bcrypt hashing with rate limiting\n"
                "from bcrypt import checkpw\n"
                "from datetime import datetime, timedelta\n"
                "\n"
                "def login(username: str, password: str):\n"
                "    if is_rate_limited(username):\n"
                "        raise TooManyAttempts()\n"
                "    user = db.query(User).filter_by(username=username).first()\n"
                "    if not user or not checkpw(password.encode(), user.password_hash):\n"
                "        record_failed_attempt(username)\n"
                "        raise InvalidCredentials()\n"
                "    return create_session(user)"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "https://cwe.mitre.org/data/definitions/287.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "Authentication failures directly enable unauthorized access and should "
        "be prioritized highly, especially for internet-facing applications."
    ),
    owasp_category="A07:2021 - Identification and Authentication Failures",
    estimated_effort_hours=6.0,
))

# ---- CWE-200: Exposure of Sensitive Information ----
_register(CWETemplate(
    cwe_id=200,
    name="Exposure of Sensitive Information",
    risk_explanation=(
        "This vulnerability occurs when the application reveals sensitive data "
        "such as technical details, personal information, or credentials in "
        "error messages, logs, API responses, or client-side code."
    ),
    impact_analysis=(
        "Information disclosure aids further attacks, exposes user PII, "
        "leaks internal system architecture details, and can violate "
        "regulatory compliance requirements (GDPR, HIPAA, PCI-DSS)."
    ),
    remediation_steps=[
        "Implement generic error messages for end users.",
        "Log detailed errors server-side only with structured logging.",
        "Remove stack traces, debug information, and verbose errors in production.",
        "Audit API responses to ensure no sensitive data leakage.",
        "Remove sensitive data from URLs and query parameters.",
        "Implement proper data classification and access controls.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: Detailed error returned to client\n"
                "try:\n"
                "    result = process_payment(card_number)\n"
                "except Exception as e:\n"
                "    return {'error': str(e), 'traceback': traceback.format_exc()}"
            ),
            "fixed": (
                "# FIXED: Generic error to client, detailed log server-side\n"
                "try:\n"
                "    result = process_payment(card_number)\n"
                "except Exception as e:\n"
                "    logger.exception('Payment processing failed')\n"
                "    return {'error': 'An internal error occurred. Please try again.'}"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "https://cwe.mitre.org/data/definitions/200.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "Information exposure may not be directly exploitable but significantly "
        "aids attackers in crafting targeted attacks against the application."
    ),
    owasp_category="A01:2021 - Broken Access Control",
    estimated_effort_hours=2.0,
))

# ---- CWE-16: Security Misconfiguration ----
_register(CWETemplate(
    cwe_id=16,
    name="Security Misconfiguration",
    risk_explanation=(
        "Security misconfiguration is the result of insecure default settings, "
        "incomplete configurations, open cloud storage, misconfigured HTTP headers, "
        "and verbose error messages containing sensitive information."
    ),
    impact_analysis=(
        "Unauthorized access to system data or functionality, potential full "
        "server compromise, information disclosure, and failure to meet "
        "compliance requirements."
    ),
    remediation_steps=[
        "Implement a repeatable hardening process for all environments.",
        "Remove or disable unused features, frameworks, and default accounts.",
        "Review and update configurations as part of the patch management process.",
        "Implement proper security headers (HSTS, X-Content-Type-Options, CSP).",
        "Automate configuration verification in CI/CD pipelines.",
        "Use infrastructure-as-code with security baselines.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: Debug mode and default secret in production\n"
                "app = Flask(__name__)\n"
                "app.config['DEBUG'] = True\n"
                "app.config['SECRET_KEY'] = 'default-secret'"
            ),
            "fixed": (
                "# FIXED: Environment-based configuration\n"
                "import os\n"
                "app = Flask(__name__)\n"
                "app.config['DEBUG'] = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'\n"
                "app.config['SECRET_KEY'] = os.environ['SECRET_KEY']  # Required env var\n"
                "app.config['SESSION_COOKIE_SECURE'] = True\n"
                "app.config['SESSION_COOKIE_HTTPONLY'] = True"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "https://cwe.mitre.org/data/definitions/16.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Configuration_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "Misconfigurations are easily exploitable and often found through "
        "automated scanning. They should be remediated as part of regular "
        "security hygiene."
    ),
    owasp_category="A05:2021 - Security Misconfiguration",
    estimated_effort_hours=2.0,
))

# ---- CWE-352: Cross-Site Request Forgery (CSRF) ----
_register(CWETemplate(
    cwe_id=352,
    name="Cross-Site Request Forgery (CSRF)",
    risk_explanation=(
        "CSRF forces authenticated users to submit unintended requests to a "
        "web application. An attacker can trick users into performing actions "
        "like changing passwords, transferring funds, or modifying settings."
    ),
    impact_analysis=(
        "Unauthorized state-changing operations performed on behalf of "
        "authenticated users, including account modification, data changes, "
        "and financial transactions."
    ),
    remediation_steps=[
        "Implement anti-CSRF tokens (synchronizer token pattern).",
        "Use SameSite cookie attribute (Strict or Lax).",
        "Verify the Origin and Referer headers for state-changing requests.",
        "Require re-authentication for sensitive operations.",
        "Use custom request headers that cannot be set cross-origin.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: No CSRF protection on state-changing endpoint\n"
                "@app.route('/transfer', methods=['POST'])\n"
                "@login_required\n"
                "def transfer_funds():\n"
                "    amount = request.form['amount']\n"
                "    to_account = request.form['to_account']\n"
                "    process_transfer(current_user, to_account, amount)"
            ),
            "fixed": (
                "# FIXED: CSRF token validation\n"
                "from flask_wtf.csrf import CSRFProtect\n"
                "csrf = CSRFProtect(app)\n"
                "\n"
                "@app.route('/transfer', methods=['POST'])\n"
                "@login_required\n"
                "@csrf.exempt  # Only if using API tokens instead\n"
                "def transfer_funds():\n"
                "    # CSRFProtect validates token automatically for form submissions\n"
                "    amount = request.form['amount']\n"
                "    to_account = request.form['to_account']\n"
                "    process_transfer(current_user, to_account, amount)"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "https://cwe.mitre.org/data/definitions/352.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "CSRF can lead to unauthorized actions on behalf of users. Priority "
        "is high for applications with sensitive state-changing operations."
    ),
    owasp_category="A01:2021 - Broken Access Control",
    estimated_effort_hours=3.0,
))

# ---- CWE-601: Open Redirect ----
_register(CWETemplate(
    cwe_id=601,
    name="Open Redirect",
    risk_explanation=(
        "Open redirect vulnerabilities allow attackers to redirect users from "
        "a trusted site to a malicious one. This is commonly exploited in "
        "phishing attacks to make malicious URLs appear legitimate."
    ),
    impact_analysis=(
        "Phishing attacks using trusted domain reputation, credential theft, "
        "malware distribution, and OAuth token theft in authorization flows."
    ),
    remediation_steps=[
        "Use an allow-list of permitted redirect destinations.",
        "Avoid using user input directly in redirect URLs.",
        "If redirects are needed, use indirect references (map IDs to URLs server-side).",
        "Validate that redirect URLs are relative (same-origin) or in the allow-list.",
        "Warn users before redirecting to external sites.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: User-controlled redirect\n"
                "@app.route('/redirect')\n"
                "def do_redirect():\n"
                "    target = request.args.get('url')\n"
                "    return redirect(target)"
            ),
            "fixed": (
                "# FIXED: Validate against allow-list\n"
                "from urllib.parse import urlparse\n"
                "ALLOWED_HOSTS = {'example.com', 'app.example.com'}\n"
                "\n"
                "@app.route('/redirect')\n"
                "def do_redirect():\n"
                "    target = request.args.get('url', '/')\n"
                "    parsed = urlparse(target)\n"
                "    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:\n"
                "        return redirect('/')\n"
                "    return redirect(target)"
            ),
        },
    },
    references=[
        "https://cwe.mitre.org/data/definitions/601.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "Open redirects are commonly exploited for phishing. Priority is medium "
        "but increases when used in authentication or OAuth flows."
    ),
    owasp_category="A01:2021 - Broken Access Control",
    estimated_effort_hours=2.0,
))

# ---- CWE-434: Unrestricted File Upload ----
_register(CWETemplate(
    cwe_id=434,
    name="Unrestricted File Upload",
    risk_explanation=(
        "Unrestricted file upload allows attackers to upload malicious files "
        "such as web shells, scripts, or executables that can be executed on "
        "the server, leading to remote code execution."
    ),
    impact_analysis=(
        "Remote code execution via uploaded web shells, server compromise, "
        "storage of malware, cross-site scripting via uploaded HTML/SVG, "
        "and denial of service via large files."
    ),
    remediation_steps=[
        "Validate file type by content (magic bytes), not just extension.",
        "Store uploaded files outside the web root.",
        "Generate random file names; do not use the original name.",
        "Set strict file size limits.",
        "Scan uploaded files for malware.",
        "Serve uploaded files with Content-Disposition: attachment header.",
        "Use a separate domain or CDN for user-uploaded content.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: No validation on upload\n"
                "@app.route('/upload', methods=['POST'])\n"
                "def upload():\n"
                "    f = request.files['file']\n"
                "    f.save(os.path.join('uploads', f.filename))"
            ),
            "fixed": (
                "# FIXED: Validate extension, content type, and rename\n"
                "import uuid\n"
                "import magic\n"
                "\n"
                "ALLOWED_TYPES = {'image/jpeg', 'image/png', 'application/pdf'}\n"
                "MAX_SIZE = 10 * 1024 * 1024  # 10MB\n"
                "\n"
                "@app.route('/upload', methods=['POST'])\n"
                "def upload():\n"
                "    f = request.files['file']\n"
                "    if f.content_length > MAX_SIZE:\n"
                "        abort(413)\n"
                "    content = f.read(2048)\n"
                "    mime = magic.from_buffer(content, mime=True)\n"
                "    if mime not in ALLOWED_TYPES:\n"
                "        abort(400, 'File type not allowed')\n"
                "    f.seek(0)\n"
                "    safe_name = f'{uuid.uuid4()}.{mime.split(\"/\")[1]}'\n"
                "    f.save(os.path.join(UPLOAD_DIR, safe_name))"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        "https://cwe.mitre.org/data/definitions/434.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "Unrestricted file upload can lead directly to remote code execution. "
        "This should be a high-priority fix for any application accepting uploads."
    ),
    owasp_category="A04:2021 - Insecure Design",
    estimated_effort_hours=4.0,
))

# ---- CWE-120: Buffer Overflow ----
_register(CWETemplate(
    cwe_id=120,
    name="Buffer Overflow",
    risk_explanation=(
        "Buffer overflow occurs when data exceeds a buffer's storage capacity "
        "and overwrites adjacent memory. This can enable arbitrary code "
        "execution, crashes, or data corruption."
    ),
    impact_analysis=(
        "Arbitrary code execution with the privileges of the vulnerable process, "
        "denial of service via crashes, data corruption, and privilege escalation."
    ),
    remediation_steps=[
        "Use memory-safe languages (Rust, Go, Python) where possible.",
        "Use safe string functions (strncpy, snprintf) instead of unsafe ones (strcpy, sprintf).",
        "Enable compiler protections: stack canaries, ASLR, DEP/NX.",
        "Perform bounds checking on all array and buffer accesses.",
        "Use static analysis tools to detect buffer overflow patterns.",
        "Consider using smart pointers or RAII patterns in C++.",
    ],
    code_examples={
        "c": {
            "vulnerable": (
                "// VULNERABLE: No bounds checking\n"
                "char buffer[64];\n"
                "strcpy(buffer, user_input);  // No size limit"
            ),
            "fixed": (
                "// FIXED: Bounds-checked copy\n"
                "char buffer[64];\n"
                "strncpy(buffer, user_input, sizeof(buffer) - 1);\n"
                "buffer[sizeof(buffer) - 1] = '\\0';"
            ),
        },
        "cpp": {
            "vulnerable": (
                "// VULNERABLE: Raw buffer operations\n"
                "char buffer[256];\n"
                "sprintf(buffer, \"Hello %s\", user_input);"
            ),
            "fixed": (
                "// FIXED: Use std::string or snprintf\n"
                "std::string greeting = \"Hello \" + std::string(user_input);\n"
                "\n"
                "// Or with C-style:\n"
                "char buffer[256];\n"
                "snprintf(buffer, sizeof(buffer), \"Hello %s\", user_input);"
            ),
        },
    },
    references=[
        "https://cwe.mitre.org/data/definitions/120.html",
        "https://owasp.org/www-community/vulnerabilities/Buffer_Overflow",
    ],
    priority_reasoning=(
        "Buffer overflows can lead to arbitrary code execution. Critical "
        "priority in C/C++ codebases, less relevant for managed languages."
    ),
    owasp_category="A06:2021 - Vulnerable and Outdated Components",
    estimated_effort_hours=6.0,
))

# ---- CWE-190: Integer Overflow ----
_register(CWETemplate(
    cwe_id=190,
    name="Integer Overflow or Wraparound",
    risk_explanation=(
        "Integer overflow occurs when an arithmetic operation results in a value "
        "too large for the integer type, causing it to wrap around. This can "
        "lead to unexpected behavior, buffer overflows, and logic flaws."
    ),
    impact_analysis=(
        "Incorrect calculations leading to buffer overflows, memory corruption, "
        "bypassed security checks, denial of service, and potential arbitrary "
        "code execution."
    ),
    remediation_steps=[
        "Use language features that detect integer overflow (checked arithmetic).",
        "Validate input ranges before arithmetic operations.",
        "Use larger integer types when overflow is possible.",
        "Implement overflow-safe arithmetic helper functions.",
        "Enable compiler warnings for implicit truncation and overflow.",
    ],
    code_examples={
        "c": {
            "vulnerable": (
                "// VULNERABLE: No overflow check\n"
                "size_t total = count * sizeof(struct item);\n"
                "char *buf = malloc(total);  // total may have wrapped to small value"
            ),
            "fixed": (
                "// FIXED: Check for overflow before allocation\n"
                "if (count > SIZE_MAX / sizeof(struct item)) {\n"
                "    return NULL;  // Overflow would occur\n"
                "}\n"
                "size_t total = count * sizeof(struct item);\n"
                "char *buf = malloc(total);"
            ),
        },
        "python": {
            "vulnerable": (
                "# Python handles big ints natively, but C-extensions may not\n"
                "# VULNERABLE: Passing unchecked Python int to C-extension\n"
                "ctypes_func(user_count)  # May truncate to 32-bit"
            ),
            "fixed": (
                "# FIXED: Validate range before passing to C-extension\n"
                "if not (0 <= user_count <= 2**31 - 1):\n"
                "    raise ValueError('Count out of valid range')\n"
                "ctypes_func(user_count)"
            ),
        },
    },
    references=[
        "https://cwe.mitre.org/data/definitions/190.html",
        "https://owasp.org/www-community/vulnerabilities/Integer_overflow",
    ],
    priority_reasoning=(
        "Integer overflow priority depends on the language and context. "
        "Critical in C/C++, lower priority in managed languages."
    ),
    owasp_category="A06:2021 - Vulnerable and Outdated Components",
    estimated_effort_hours=4.0,
))

# ---- CWE-362: Race Condition ----
_register(CWETemplate(
    cwe_id=362,
    name="Race Condition",
    risk_explanation=(
        "Race conditions occur when multiple threads or processes access shared "
        "resources concurrently without proper synchronization. This can lead "
        "to time-of-check to time-of-use (TOCTOU) vulnerabilities."
    ),
    impact_analysis=(
        "Privilege escalation, authentication bypass, data corruption, "
        "double-spending in financial applications, and file system "
        "manipulation via symlink attacks."
    ),
    remediation_steps=[
        "Use atomic operations and proper locking mechanisms.",
        "Implement database-level locking (SELECT FOR UPDATE) for critical sections.",
        "Use file-level locks for filesystem operations.",
        "Design for idempotency to reduce impact of concurrent operations.",
        "Use transactions with appropriate isolation levels.",
        "Employ optimistic concurrency control with version fields.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: TOCTOU race condition\n"
                "if user.balance >= amount:          # Check\n"
                "    user.balance -= amount           # Use\n"
                "    db.session.commit()"
            ),
            "fixed": (
                "# FIXED: Database-level atomic operation\n"
                "from sqlalchemy import update\n"
                "result = db.session.execute(\n"
                "    update(User)\n"
                "    .where(User.id == user.id)\n"
                "    .where(User.balance >= amount)  # Atomic check-and-update\n"
                "    .values(balance=User.balance - amount)\n"
                ")\n"
                "if result.rowcount == 0:\n"
                "    raise InsufficientFunds()"
            ),
        },
    },
    references=[
        "https://cwe.mitre.org/data/definitions/362.html",
        "https://owasp.org/www-community/vulnerabilities/Race_Conditions",
    ],
    priority_reasoning=(
        "Race conditions are high priority in financial and authentication "
        "contexts. They can be difficult to reproduce but easy to exploit."
    ),
    owasp_category="A04:2021 - Insecure Design",
    estimated_effort_hours=6.0,
))

# ---- CWE-798: Hard-coded Credentials ----
_register(CWETemplate(
    cwe_id=798,
    name="Hard-coded Credentials",
    risk_explanation=(
        "Hard-coded credentials in source code provide attackers with direct "
        "access to systems and services. These credentials are easily "
        "discoverable through code review, reverse engineering, or leaks."
    ),
    impact_analysis=(
        "Unauthorized access to databases, APIs, and services. Hard-coded "
        "credentials cannot be rotated without code changes and deployments, "
        "making incident response slow and difficult."
    ),
    remediation_steps=[
        "Move all credentials to environment variables or a secrets manager.",
        "Use a vault service (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).",
        "Implement credential rotation policies.",
        "Add pre-commit hooks to detect secrets (git-secrets, detect-secrets).",
        "Scan repositories for accidentally committed secrets.",
        "Revoke and rotate any credentials found in source code immediately.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: Hard-coded credentials\n"
                "DB_PASSWORD = 'super_secret_password_123'\n"
                "API_KEY = 'sk-1234567890abcdef'\n"
                "conn = psycopg2.connect(password=DB_PASSWORD)"
            ),
            "fixed": (
                "# FIXED: Use environment variables or secrets manager\n"
                "import os\n"
                "\n"
                "DB_PASSWORD = os.environ['DB_PASSWORD']\n"
                "API_KEY = os.environ['API_KEY']\n"
                "\n"
                "# Or use a secrets manager:\n"
                "# from aws_secretsmanager import get_secret\n"
                "# DB_PASSWORD = get_secret('prod/db/password')"
            ),
        },
        "javascript": {
            "vulnerable": (
                "// VULNERABLE: Hard-coded API key\n"
                "const API_KEY = 'sk-1234567890abcdef';\n"
                "const client = new APIClient({ apiKey: API_KEY });"
            ),
            "fixed": (
                "// FIXED: Use environment variables\n"
                "const API_KEY = process.env.API_KEY;\n"
                "if (!API_KEY) throw new Error('API_KEY is required');\n"
                "const client = new APIClient({ apiKey: API_KEY });"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "Hard-coded credentials are a critical finding that enables immediate "
        "unauthorized access. Remediation and rotation should be immediate."
    ),
    owasp_category="A07:2021 - Identification and Authentication Failures",
    estimated_effort_hours=2.0,
))

# ---- CWE-327: Use of Broken or Risky Cryptographic Algorithm ----
_register(CWETemplate(
    cwe_id=327,
    name="Use of Broken or Risky Cryptographic Algorithm",
    risk_explanation=(
        "Using weak or broken cryptographic algorithms (MD5, SHA1 for security, "
        "DES, RC4) provides a false sense of security. These algorithms have "
        "known vulnerabilities and can be broken with modern computing."
    ),
    impact_analysis=(
        "Data exposed through broken encryption, forged digital signatures, "
        "password cracking, and man-in-the-middle attacks. Violates "
        "compliance requirements (PCI-DSS, HIPAA)."
    ),
    remediation_steps=[
        "Replace MD5/SHA1 with SHA-256 or SHA-3 for hashing.",
        "Use Argon2, bcrypt, or scrypt for password hashing.",
        "Replace DES/3DES/RC4 with AES-256-GCM for encryption.",
        "Use TLS 1.2+ with strong cipher suites.",
        "Use cryptographic libraries rather than implementing crypto manually.",
        "Implement key management with proper rotation policies.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: MD5 for password hashing\n"
                "import hashlib\n"
                "password_hash = hashlib.md5(password.encode()).hexdigest()"
            ),
            "fixed": (
                "# FIXED: Use bcrypt for passwords, SHA-256 for data integrity\n"
                "import bcrypt\n"
                "password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n"
                "\n"
                "# For data integrity:\n"
                "import hashlib\n"
                "data_hash = hashlib.sha256(data.encode()).hexdigest()"
            ),
        },
        "javascript": {
            "vulnerable": (
                "// VULNERABLE: MD5 hashing\n"
                "const hash = crypto.createHash('md5').update(password).digest('hex');"
            ),
            "fixed": (
                "// FIXED: Use bcrypt for passwords\n"
                "const bcrypt = require('bcrypt');\n"
                "const hash = await bcrypt.hash(password, 12);"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "Weak cryptography undermines all security controls that depend on it. "
        "Priority is high, especially for password storage and data encryption."
    ),
    owasp_category="A02:2021 - Cryptographic Failures",
    estimated_effort_hours=4.0,
))

# ---- CWE-862: Missing Authorization ----
_register(CWETemplate(
    cwe_id=862,
    name="Missing Authorization",
    risk_explanation=(
        "Missing authorization occurs when the application does not verify "
        "that the authenticated user has the required privileges to access "
        "a resource or perform an action, leading to privilege escalation."
    ),
    impact_analysis=(
        "Unauthorized access to other users' data (IDOR), privilege escalation "
        "to admin functions, horizontal and vertical access control bypasses, "
        "and data modification by unauthorized users."
    ),
    remediation_steps=[
        "Implement role-based access control (RBAC) or attribute-based access control (ABAC).",
        "Check authorization on every request, not just at the UI level.",
        "Use server-side ownership checks for all resource access.",
        "Deny access by default; use explicit allow rules.",
        "Centralize authorization logic in middleware or decorators.",
        "Log and alert on authorization failures.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: No authorization check on resource access\n"
                "@app.route('/api/users/<user_id>/data')\n"
                "@login_required\n"
                "def get_user_data(user_id):\n"
                "    data = db.query(UserData).filter_by(user_id=user_id).all()\n"
                "    return jsonify(data)  # Any authenticated user can access any user's data"
            ),
            "fixed": (
                "# FIXED: Verify resource ownership\n"
                "@app.route('/api/users/<user_id>/data')\n"
                "@login_required\n"
                "def get_user_data(user_id):\n"
                "    if str(current_user.id) != user_id and not current_user.is_admin:\n"
                "        abort(403, 'Access denied')\n"
                "    data = db.query(UserData).filter_by(user_id=user_id).all()\n"
                "    return jsonify(data)"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "https://cwe.mitre.org/data/definitions/862.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "Missing authorization is a critical access control flaw. Priority is "
        "highest for endpoints that access sensitive data or perform privileged actions."
    ),
    owasp_category="A01:2021 - Broken Access Control",
    estimated_effort_hours=4.0,
))

# ---- CWE-20: Improper Input Validation ----
_register(CWETemplate(
    cwe_id=20,
    name="Improper Input Validation",
    risk_explanation=(
        "Improper input validation occurs when the application does not "
        "properly validate user input, allowing attackers to supply "
        "unexpected data that can trigger various vulnerabilities."
    ),
    impact_analysis=(
        "Enables a wide range of attacks including injection, buffer overflow, "
        "denial of service, business logic bypass, and data corruption. "
        "Input validation is the first line of defense."
    ),
    remediation_steps=[
        "Validate all input on the server side using strict allow-lists.",
        "Define and enforce input schemas (type, length, format, range).",
        "Use data validation libraries (Pydantic, Joi, JSON Schema).",
        "Reject invalid input rather than attempting to sanitize it.",
        "Implement validation at the API gateway level for consistent enforcement.",
        "Log validation failures for security monitoring.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: No input validation\n"
                "@app.route('/api/users/<user_id>')\n"
                "def get_user(user_id):\n"
                "    return db.query(User).get(user_id)  # user_id could be anything"
            ),
            "fixed": (
                "# FIXED: Strict input validation with Pydantic\n"
                "from pydantic import BaseModel, conint\n"
                "\n"
                "class UserIdParam(BaseModel):\n"
                "    user_id: conint(gt=0, lt=2**31)\n"
                "\n"
                "@app.route('/api/users/<int:user_id>')\n"
                "def get_user(user_id: int):\n"
                "    validated = UserIdParam(user_id=user_id)\n"
                "    user = db.query(User).get(validated.user_id)\n"
                "    if not user:\n"
                "        abort(404)\n"
                "    return user"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://cwe.mitre.org/data/definitions/20.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "Input validation is foundational to security. While the CWE itself "
        "is broad, the specific vulnerability context determines priority."
    ),
    owasp_category="A03:2021 - Injection",
    estimated_effort_hours=3.0,
))

# ---- CWE-306: Missing Authentication for Critical Function ----
_register(CWETemplate(
    cwe_id=306,
    name="Missing Authentication for Critical Function",
    risk_explanation=(
        "Critical functions that lack authentication can be accessed by "
        "anyone, including unauthenticated attackers. This is distinct from "
        "missing authorization (CWE-862) in that no authentication is "
        "required at all."
    ),
    impact_analysis=(
        "Complete bypass of authentication controls, unauthorized access to "
        "administrative functions, data manipulation, and system compromise."
    ),
    remediation_steps=[
        "Require authentication for all non-public endpoints.",
        "Implement authentication checks in middleware/framework level.",
        "Audit all endpoints to ensure authentication is enforced.",
        "Use default-deny patterns where new endpoints require auth automatically.",
        "Implement API gateway authentication for microservices.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: Admin endpoint with no authentication\n"
                "@app.route('/admin/delete-user/<user_id>', methods=['DELETE'])\n"
                "def delete_user(user_id):\n"
                "    db.query(User).filter_by(id=user_id).delete()\n"
                "    return {'status': 'deleted'}"
            ),
            "fixed": (
                "# FIXED: Require authentication and admin role\n"
                "@app.route('/admin/delete-user/<user_id>', methods=['DELETE'])\n"
                "@login_required\n"
                "@admin_required\n"
                "def delete_user(user_id):\n"
                "    db.query(User).filter_by(id=user_id).delete()\n"
                "    return {'status': 'deleted'}"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "https://cwe.mitre.org/data/definitions/306.html",
    ],
    priority_reasoning=(
        "Missing authentication on critical functions is a critical severity "
        "finding that allows unauthenticated access to privileged operations."
    ),
    owasp_category="A07:2021 - Identification and Authentication Failures",
    estimated_effort_hours=3.0,
))

# ---- CWE-732: Incorrect Permission Assignment ----
_register(CWETemplate(
    cwe_id=732,
    name="Incorrect Permission Assignment for Critical Resource",
    risk_explanation=(
        "Incorrect permissions on files, directories, or resources allow "
        "unauthorized users to read, modify, or execute critical assets "
        "such as configuration files, credentials, and executables."
    ),
    impact_analysis=(
        "Unauthorized read access to secrets and configuration, modification "
        "of application code or configuration, and potential privilege escalation "
        "through writable executables."
    ),
    remediation_steps=[
        "Apply the principle of least privilege to all file and directory permissions.",
        "Set configuration files to read-only for the application user.",
        "Ensure credentials files are readable only by the owning service.",
        "Audit file permissions as part of deployment pipelines.",
        "Use infrastructure-as-code to enforce permission standards.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: World-readable credentials file\n"
                "os.chmod('/etc/app/secrets.conf', 0o644)  # Anyone can read"
            ),
            "fixed": (
                "# FIXED: Restrict to owner only\n"
                "os.chmod('/etc/app/secrets.conf', 0o600)  # Owner read/write only"
            ),
        },
        "shell": {
            "vulnerable": (
                "# VULNERABLE: World-readable private key\n"
                "chmod 644 /etc/ssl/private/server.key"
            ),
            "fixed": (
                "# FIXED: Restrict private key access\n"
                "chmod 600 /etc/ssl/private/server.key\n"
                "chown root:root /etc/ssl/private/server.key"
            ),
        },
    },
    references=[
        "https://cwe.mitre.org/data/definitions/732.html",
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    ],
    priority_reasoning=(
        "Incorrect permissions on critical resources can enable escalation "
        "and unauthorized access. Priority depends on the sensitivity of the resource."
    ),
    owasp_category="A01:2021 - Broken Access Control",
    estimated_effort_hours=1.0,
))

# ---- CWE-319: Cleartext Transmission ----
_register(CWETemplate(
    cwe_id=319,
    name="Cleartext Transmission of Sensitive Information",
    risk_explanation=(
        "Transmitting sensitive data over unencrypted channels (HTTP, FTP, "
        "SMTP without TLS) exposes it to interception via network sniffing, "
        "man-in-the-middle attacks, and passive eavesdropping."
    ),
    impact_analysis=(
        "Credential theft, session hijacking, personal data exposure, "
        "and regulatory compliance violations. Particularly severe on "
        "public or shared networks."
    ),
    remediation_steps=[
        "Enforce HTTPS for all communications using TLS 1.2+.",
        "Implement HSTS (HTTP Strict Transport Security) headers.",
        "Redirect all HTTP requests to HTTPS.",
        "Use encrypted protocols (SFTP, SMTPS, LDAPS) for backend services.",
        "Pin certificates or use certificate transparency for high-security apps.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: HTTP connection for sensitive data\n"
                "import requests\n"
                "response = requests.post('http://api.example.com/login',\n"
                "                        data={'password': user_password})"
            ),
            "fixed": (
                "# FIXED: Enforce HTTPS with certificate verification\n"
                "import requests\n"
                "response = requests.post('https://api.example.com/login',\n"
                "                        data={'password': user_password},\n"
                "                        verify=True)"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "https://cwe.mitre.org/data/definitions/319.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "Cleartext transmission of credentials or PII is a high-priority "
        "finding, especially for internet-facing applications."
    ),
    owasp_category="A02:2021 - Cryptographic Failures",
    estimated_effort_hours=2.0,
))

# ---- CWE-522: Insufficiently Protected Credentials ----
_register(CWETemplate(
    cwe_id=522,
    name="Insufficiently Protected Credentials",
    risk_explanation=(
        "Credentials stored, transmitted, or managed without adequate protection "
        "are vulnerable to theft. This includes plaintext storage, weak hashing, "
        "and insecure credential recovery mechanisms."
    ),
    impact_analysis=(
        "Mass credential compromise if the storage is breached, account "
        "takeover, lateral movement using stolen credentials, and regulatory "
        "violations."
    ),
    remediation_steps=[
        "Hash passwords using Argon2id, bcrypt, or scrypt with appropriate cost factors.",
        "Never store passwords in plaintext or with reversible encryption.",
        "Use unique salts per password (handled automatically by bcrypt/Argon2).",
        "Implement secure credential recovery (time-limited tokens, not security questions).",
        "Enforce password complexity and length requirements.",
        "Monitor for credential stuffing and breached password reuse.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: Plaintext password storage\n"
                "user.password = request.form['password']\n"
                "# or weak hash:\n"
                "user.password = hashlib.sha1(password.encode()).hexdigest()"
            ),
            "fixed": (
                "# FIXED: Argon2 hashing\n"
                "from argon2 import PasswordHasher\n"
                "ph = PasswordHasher()\n"
                "user.password_hash = ph.hash(request.form['password'])\n"
                "\n"
                "# Verification:\n"
                "try:\n"
                "    ph.verify(user.password_hash, submitted_password)\n"
                "except argon2.exceptions.VerifyMismatchError:\n"
                "    raise InvalidCredentials()"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "https://cwe.mitre.org/data/definitions/522.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
    ],
    priority_reasoning=(
        "Weak credential storage is a critical finding. A database breach "
        "with poorly hashed passwords leads to mass account compromise."
    ),
    owasp_category="A07:2021 - Identification and Authentication Failures",
    estimated_effort_hours=3.0,
))

# ---- CWE-269: Improper Privilege Management ----
_register(CWETemplate(
    cwe_id=269,
    name="Improper Privilege Management",
    risk_explanation=(
        "Improper privilege management occurs when applications do not properly "
        "restrict user privileges, allowing users to perform actions beyond "
        "their intended authorization level."
    ),
    impact_analysis=(
        "Privilege escalation from regular user to admin, unauthorized access "
        "to sensitive operations, data manipulation, and system compromise."
    ),
    remediation_steps=[
        "Implement the principle of least privilege throughout the application.",
        "Use role-based access control (RBAC) with well-defined roles.",
        "Validate privileges server-side on every privileged operation.",
        "Separate duties to prevent single points of privilege abuse.",
        "Audit privilege assignments regularly.",
        "Implement privilege de-escalation for operations that do not need elevated access.",
    ],
    code_examples={
        "python": {
            "vulnerable": (
                "# VULNERABLE: Client-side role check only\n"
                "@app.route('/admin/settings', methods=['POST'])\n"
                "@login_required\n"
                "def update_settings():\n"
                "    # Relies on UI hiding the admin button\n"
                "    return update_system_settings(request.json)"
            ),
            "fixed": (
                "# FIXED: Server-side role verification\n"
                "@app.route('/admin/settings', methods=['POST'])\n"
                "@login_required\n"
                "def update_settings():\n"
                "    if current_user.role != 'admin':\n"
                "        abort(403, 'Admin privileges required')\n"
                "    return update_system_settings(request.json)"
            ),
        },
    },
    references=[
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "https://cwe.mitre.org/data/definitions/269.html",
    ],
    priority_reasoning=(
        "Privilege management flaws allow escalation attacks. Priority is "
        "critical for multi-tenant or role-based applications."
    ),
    owasp_category="A01:2021 - Broken Access Control",
    estimated_effort_hours=4.0,
))


# ---------------------------------------------------------------------------
# Fallback template for unknown CWEs
# ---------------------------------------------------------------------------

FALLBACK_TEMPLATE = CWETemplate(
    cwe_id=0,
    name="Security Vulnerability",
    risk_explanation=(
        "This finding indicates a security vulnerability that could be "
        "exploited by attackers to compromise the application's confidentiality, "
        "integrity, or availability."
    ),
    impact_analysis=(
        "Impact varies based on the vulnerability type and context. "
        "Review the finding details to understand the specific risk "
        "to your application and data."
    ),
    remediation_steps=[
        "Review the finding details and understand the root cause.",
        "Consult the CWE reference for detailed vulnerability information.",
        "Apply the principle of least privilege and defense in depth.",
        "Implement input validation and output encoding where applicable.",
        "Follow secure coding guidelines for your technology stack.",
        "Add automated security tests to prevent regressions.",
        "Consider a security code review of the affected component.",
    ],
    code_examples={
        "python": {
            "vulnerable": "# Review the specific finding for vulnerable code patterns.",
            "fixed": "# Apply the remediation steps above to the specific code location.",
        },
    },
    references=[
        "https://owasp.org/Top10/",
        "https://cwe.mitre.org/",
        "https://cheatsheetseries.owasp.org/",
    ],
    priority_reasoning=(
        "Priority should be assessed based on severity, exploitability, "
        "and the business context of the affected component."
    ),
    owasp_category="General",
    estimated_effort_hours=4.0,
)


# ---------------------------------------------------------------------------
# Data classes for results
# ---------------------------------------------------------------------------

@dataclass
class RemediationResult:
    finding_id: int
    finding_title: str
    cwe_id: Optional[int]
    cwe_name: str
    severity: str
    risk_explanation: str
    impact_analysis: str
    remediation_steps: list[str]
    code_example_vulnerable: str
    code_example_fixed: str
    code_language: str
    references: list[str]
    priority_reasoning: str
    owasp_category: str
    estimated_effort: dict
    confidence: str  # "high" if CWE matched, "medium" for fallback
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "finding_title": self.finding_title,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "severity": self.severity,
            "risk_explanation": self.risk_explanation,
            "impact_analysis": self.impact_analysis,
            "remediation_steps": self.remediation_steps,
            "code_example_vulnerable": self.code_example_vulnerable,
            "code_example_fixed": self.code_example_fixed,
            "code_language": self.code_language,
            "references": self.references,
            "priority_reasoning": self.priority_reasoning,
            "owasp_category": self.owasp_category,
            "estimated_effort": self.estimated_effort,
            "confidence": self.confidence,
            "generated_at": self.generated_at,
        }


@dataclass
class DeveloperSummary:
    finding_id: int
    title: str
    one_liner: str
    what_to_fix: str
    how_to_fix: str
    quick_code_hint: str
    effort_label: str

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "one_liner": self.one_liner,
            "what_to_fix": self.what_to_fix,
            "how_to_fix": self.how_to_fix,
            "quick_code_hint": self.quick_code_hint,
            "effort_label": self.effort_label,
        }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class AICopilotService:
    """Rule-based remediation engine that generates AI-quality fix suggestions."""

    def __init__(self) -> None:
        self.templates = CWE_TEMPLATES
        self.fallback = FALLBACK_TEMPLATE

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_template(self, cwe_id: Optional[int]) -> tuple[CWETemplate, str]:
        """Return (template, confidence) for a CWE ID."""
        if cwe_id and cwe_id in self.templates:
            return self.templates[cwe_id], "high"
        return self.fallback, "medium"

    def _select_code_example(
        self, template: CWETemplate, language: str
    ) -> tuple[str, str, str]:
        """Select the best code example for the detected language.

        Returns (vulnerable, fixed, language_used).
        """
        examples = template.code_examples
        if language in examples:
            ex = examples[language]
            return ex["vulnerable"], ex["fixed"], language

        # Fallback chain: python -> javascript -> java -> first available
        for fallback_lang in ("python", "javascript", "java"):
            if fallback_lang in examples:
                ex = examples[fallback_lang]
                return ex["vulnerable"], ex["fixed"], fallback_lang

        # Last resort: pick the first one
        if examples:
            lang = next(iter(examples))
            ex = examples[lang]
            return ex["vulnerable"], ex["fixed"], lang

        return (
            "# No code example available for this vulnerability type.",
            "# Apply the remediation steps above to your code.",
            "text",
        )

    def _compute_effort(self, severity: str, template: CWETemplate) -> dict:
        """Compute estimated remediation effort."""
        sev = severity.lower() if severity else "medium"
        base = EFFORT_BY_SEVERITY.get(sev, EFFORT_BY_SEVERITY["medium"])
        return {
            "estimated_hours": template.estimated_effort_hours,
            "range_min_hours": base["min_hours"],
            "range_max_hours": base["max_hours"],
            "complexity_label": base["label"],
        }

    def _build_priority_reasoning(
        self, template: CWETemplate, finding: Finding
    ) -> str:
        """Build contextual priority reasoning."""
        parts = [template.priority_reasoning]

        severity = finding.severity.value if finding.severity else "medium"
        if severity in ("critical", "high"):
            parts.append(
                f"The {severity} severity rating further elevates the "
                f"remediation priority."
            )

        file_path = finding.file_path or ""
        if any(
            kw in file_path.lower()
            for kw in ("auth", "login", "payment", "admin", "crypto", "secret")
        ):
            parts.append(
                "The affected file path indicates a security-sensitive "
                "component, which increases the urgency of remediation."
            )

        return " ".join(parts)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_remediation(self, finding: Finding) -> RemediationResult:
        """Generate detailed remediation advice for a single finding."""
        cwe_id = finding.cwe
        template, confidence = self._get_template(cwe_id)
        language = _detect_language(finding.file_path)
        vuln_code, fixed_code, lang_used = self._select_code_example(
            template, language
        )
        severity = finding.severity.value if finding.severity else "medium"

        return RemediationResult(
            finding_id=finding.id,
            finding_title=finding.title,
            cwe_id=cwe_id,
            cwe_name=template.name,
            severity=severity,
            risk_explanation=template.risk_explanation,
            impact_analysis=template.impact_analysis,
            remediation_steps=template.remediation_steps,
            code_example_vulnerable=vuln_code,
            code_example_fixed=fixed_code,
            code_language=lang_used,
            references=template.references,
            priority_reasoning=self._build_priority_reasoning(template, finding),
            owasp_category=template.owasp_category,
            estimated_effort=self._compute_effort(severity, template),
            confidence=confidence,
        )

    def generate_bulk_remediation(
        self, findings: list[Finding]
    ) -> list[RemediationResult]:
        """Generate remediation advice for multiple findings."""
        return [self.generate_remediation(f) for f in findings]

    def get_developer_summary(self, finding: Finding) -> DeveloperSummary:
        """Generate a short, developer-friendly summary for a finding."""
        cwe_id = finding.cwe
        template, _ = self._get_template(cwe_id)
        language = _detect_language(finding.file_path)
        _, fixed_code, _ = self._select_code_example(template, language)
        severity = finding.severity.value if finding.severity else "medium"
        effort = EFFORT_BY_SEVERITY.get(severity, EFFORT_BY_SEVERITY["medium"])

        # Build a short one-liner
        cwe_label = f"CWE-{cwe_id}" if cwe_id else "Security"
        one_liner = (
            f"{cwe_label}: {template.name} ({severity.upper()}) "
            f"found in {finding.file_path or 'unknown location'}."
        )

        # First remediation step as the quick "how to fix"
        how_to_fix = template.remediation_steps[0] if template.remediation_steps else (
            "Review the finding and apply secure coding practices."
        )

        # Extract a short code hint (first 3 lines of the fixed example)
        hint_lines = fixed_code.strip().split("\n")[:3]
        quick_hint = "\n".join(hint_lines)

        return DeveloperSummary(
            finding_id=finding.id,
            title=finding.title,
            one_liner=one_liner,
            what_to_fix=template.risk_explanation[:200] + (
                "..." if len(template.risk_explanation) > 200 else ""
            ),
            how_to_fix=how_to_fix,
            quick_code_hint=quick_hint,
            effort_label=effort["label"],
        )

    def get_coverage_stats(self) -> dict:
        """Return statistics about remediation template coverage."""
        covered_cwes = sorted(self.templates.keys())
        return {
            "total_cwe_templates": len(self.templates),
            "covered_cwes": covered_cwes,
            "languages_supported": sorted(set(LANG_MAP.values())),
            "severity_levels": list(EFFORT_BY_SEVERITY.keys()),
            "has_fallback": True,
        }
