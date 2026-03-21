// Mock data generated from real API responses
// This file enables demo mode without a backend

export const findings = [
  {
    "id": 164,
    "title": "CVE-2023-50495 in ncurses",
    "description": "ncurses before 6.4 allows segfault via crafted terminfo file.",
    "severity": "low",
    "status": "active",
    "cvss_score": null,
    "cwe": null,
    "cve": "CVE-2023-50495",
    "scanner": "Trivy",
    "tool_type": "SCA",
    "file_path": "Dockerfile",
    "line_number": null,
    "component": "ncurses",
    "component_version": "6.3-2",
    "is_duplicate": true,
    "mitigation": "Update to 6.4+20231016",
    "product_id": 5,
    "date_found": "2026-03-20T13:32:12.344258Z",
    "created_at": "2026-03-20T13:32:12.344259Z"
  },
  {
    "id": 163,
    "title": "CVE-2024-2961 in glibc",
    "description": "Buffer overflow in glibc iconv when converting to ISO-2022-CN-EXT character set.",
    "severity": "high",
    "status": "active",
    "cvss_score": null,
    "cwe": null,
    "cve": "CVE-2024-2961",
    "scanner": "Trivy",
    "tool_type": "SCA",
    "file_path": "Dockerfile",
    "line_number": null,
    "component": "glibc",
    "component_version": "2.35",
    "is_duplicate": true,
    "mitigation": "Update to 2.35-0ubuntu3.8",
    "product_id": 5,
    "date_found": "2026-03-20T13:32:12.342603Z",
    "created_at": "2026-03-20T13:32:12.342604Z"
  },
  {
    "id": 162,
    "title": "CVE-2024-32002 in git",
    "description": "Git before 2.39.4 allows remote code execution during recursive clone with crafted submodules.",
    "severity": "critical",
    "status": "active",
    "cvss_score": null,
    "cwe": null,
    "cve": "CVE-2024-32002",
    "scanner": "Trivy",
    "tool_type": "SCA",
    "file_path": "Dockerfile",
    "line_number": null,
    "component": "git",
    "component_version": "2.39.2",
    "is_duplicate": true,
    "mitigation": "Update to 2.39.4",
    "product_id": 5,
    "date_found": "2026-03-20T13:32:12.341216Z",
    "created_at": "2026-03-20T13:32:12.341217Z"
  },
  {
    "id": 161,
    "title": "CVE-2024-21538 in cross-spawn",
    "description": "Cross-spawn before 7.0.5 allows ReDoS via crafted command arguments.",
    "severity": "high",
    "status": "active",
    "cvss_score": null,
    "cwe": null,
    "cve": "CVE-2024-21538",
    "scanner": "Trivy",
    "tool_type": "SCA",
    "file_path": "package-lock.json",
    "line_number": null,
    "component": "cross-spawn",
    "component_version": "7.0.3",
    "is_duplicate": true,
    "mitigation": "Update to 7.0.5",
    "product_id": 5,
    "date_found": "2026-03-20T13:32:12.339722Z",
    "created_at": "2026-03-20T13:32:12.339723Z"
  },
  {
    "id": 160,
    "title": "CVE-2024-37890 in ws",
    "description": "ws before 7.5.10 vulnerable to DoS when Sec-WebSocket-Protocol header has excessive length.",
    "severity": "high",
    "status": "active",
    "cvss_score": null,
    "cwe": null,
    "cve": "CVE-2024-37890",
    "scanner": "Trivy",
    "tool_type": "SCA",
    "file_path": "package-lock.json",
    "line_number": null,
    "component": "ws",
    "component_version": "7.5.9",
    "is_duplicate": true,
    "mitigation": "Update to 7.5.10",
    "product_id": 5,
    "date_found": "2026-03-20T13:32:12.338141Z",
    "created_at": "2026-03-20T13:32:12.338143Z"
  },
  {
    "id": 159,
    "title": "CVE-2023-26159 in follow-redirects",
    "description": "Improper URL handling allows attacks via hostname manipulation.",
    "severity": "medium",
    "status": "active",
    "cvss_score": null,
    "cwe": null,
    "cve": "CVE-2023-26159",
    "scanner": "Trivy",
    "tool_type": "SCA",
    "file_path": "package-lock.json",
    "line_number": null,
    "component": "follow-redirects",
    "component_version": "1.15.2",
    "is_duplicate": true,
    "mitigation": "Update to 1.15.4",
    "product_id": 5,
    "date_found": "2026-03-20T13:32:12.336769Z",
    "created_at": "2026-03-20T13:32:12.336770Z"
  },
  {
    "id": 158,
    "title": "CVE-2024-28849 in follow-redirects",
    "description": "Follow-redirects before 1.15.6 leaks Authorization headers on cross-origin redirect.",
    "severity": "medium",
    "status": "active",
    "cvss_score": null,
    "cwe": null,
    "cve": "CVE-2024-28849",
    "scanner": "Trivy",
    "tool_type": "SCA",
    "file_path": "package-lock.json",
    "line_number": null,
    "component": "follow-redirects",
    "component_version": "1.15.2",
    "is_duplicate": true,
    "mitigation": "Update to 1.15.6",
    "product_id": 5,
    "date_found": "2026-03-20T13:32:12.334976Z",
    "created_at": "2026-03-20T13:32:12.334977Z"
  },
  {
    "id": 157,
    "title": "CVE-2023-44270 in postcss",
    "description": "PostCSS before 8.4.31 misparses external CSS with line returns.",
    "severity": "medium",
    "status": "active",
    "cvss_score": null,
    "cwe": null,
    "cve": "CVE-2023-44270",
    "scanner": "Trivy",
    "tool_type": "SCA",
    "file_path": "package-lock.json",
    "line_number": null,
    "component": "postcss",
    "component_version": "8.4.14",
    "is_duplicate": true,
    "mitigation": "Update to 8.4.31",
    "product_id": 5,
    "date_found": "2026-03-20T13:32:12.333740Z",
    "created_at": "2026-03-20T13:32:12.333741Z"
  },
  {
    "id": 156,
    "title": "CVE-2024-4068 in braces",
    "description": "Braces before 3.0.3 is vulnerable to Regular Expression Denial of Service.",
    "severity": "high",
    "status": "active",
    "cvss_score": null,
    "cwe": null,
    "cve": "CVE-2024-4068",
    "scanner": "Trivy",
    "tool_type": "SCA",
    "file_path": "package-lock.json",
    "line_number": null,
    "component": "braces",
    "component_version": "3.0.2",
    "is_duplicate": true,
    "mitigation": "Update to 3.0.3",
    "product_id": 5,
    "date_found": "2026-03-20T13:32:12.332378Z",
    "created_at": "2026-03-20T13:32:12.332379Z"
  },
  {
    "id": 155,
    "title": "CVE-2024-29041 in express",
    "description": "Express before 4.19.2 allows response splitting via untrusted input in res.location().",
    "severity": "high",
    "status": "active",
    "cvss_score": null,
    "cwe": null,
    "cve": "CVE-2024-29041",
    "scanner": "Trivy",
    "tool_type": "SCA",
    "file_path": "package-lock.json",
    "line_number": null,
    "component": "express",
    "component_version": "4.17.1",
    "is_duplicate": true,
    "mitigation": "Update to 4.19.2",
    "product_id": 5,
    "date_found": "2026-03-20T13:32:12.330838Z",
    "created_at": "2026-03-20T13:32:12.330840Z"
  },
  {
    "id": 154,
    "title": "CVE-2024-38996 in express",
    "description": "Express before 4.19.2 allows open redirect via malicious URL in redirect().",
    "severity": "critical",
    "status": "active",
    "cvss_score": null,
    "cwe": null,
    "cve": "CVE-2024-38996",
    "scanner": "Trivy",
    "tool_type": "SCA",
    "file_path": "package-lock.json",
    "line_number": null,
    "component": "express",
    "component_version": "4.17.1",
    "is_duplicate": true,
    "mitigation": "Update to 4.19.2",
    "product_id": 5,
    "date_found": "2026-03-20T13:32:12.328445Z",
    "created_at": "2026-03-20T13:32:12.328447Z"
  },
  {
    "id": 153,
    "title": "python.lang.security.audit.insecure-jwt",
    "description": "JWT token with algorithm none allows token forgery without secret key.",
    "severity": "high",
    "status": "active",
    "cvss_score": null,
    "cwe": 287,
    "cve": null,
    "scanner": "Semgrep",
    "tool_type": "SAST",
    "file_path": "src/auth/token_service.py",
    "line_number": 22,
    "component": null,
    "component_version": null,
    "is_duplicate": true,
    "mitigation": "",
    "product_id": 4,
    "date_found": "2026-03-20T13:32:12.283263Z",
    "created_at": "2026-03-20T13:32:12.283264Z"
  },
  {
    "id": 152,
    "title": "python.lang.security.audit.csrf-disabled",
    "description": "CSRF protection explicitly disabled allowing cross-site request forgery.",
    "severity": "medium",
    "status": "active",
    "cvss_score": null,
    "cwe": 352,
    "cve": null,
    "scanner": "Semgrep",
    "tool_type": "SAST",
    "file_path": "src/config/security.py",
    "line_number": 15,
    "component": null,
    "component_version": null,
    "is_duplicate": true,
    "mitigation": "",
    "product_id": 4,
    "date_found": "2026-03-20T13:32:12.281445Z",
    "created_at": "2026-03-20T13:32:12.281447Z"
  },
  {
    "id": 151,
    "title": "python.lang.security.audit.path-traversal",
    "description": "User input in file path without sanitization. Path traversal vulnerability.",
    "severity": "high",
    "status": "active",
    "cvss_score": null,
    "cwe": 22,
    "cve": null,
    "scanner": "Semgrep",
    "tool_type": "SAST",
    "file_path": "src/services/file_service.py",
    "line_number": 33,
    "component": null,
    "component_version": null,
    "is_duplicate": true,
    "mitigation": "",
    "product_id": 4,
    "date_found": "2026-03-20T13:32:12.280071Z",
    "created_at": "2026-03-20T13:32:12.280072Z"
  },
  {
    "id": 150,
    "title": "python.lang.security.audit.open-redirect",
    "description": "Open redirect vulnerability. Redirect URL controlled by user input.",
    "severity": "medium",
    "status": "active",
    "cvss_score": null,
    "cwe": 601,
    "cve": null,
    "scanner": "Semgrep",
    "tool_type": "SAST",
    "file_path": "src/auth/login_controller.py",
    "line_number": 78,
    "component": null,
    "component_version": null,
    "is_duplicate": true,
    "mitigation": "",
    "product_id": 4,
    "date_found": "2026-03-20T13:32:12.278528Z",
    "created_at": "2026-03-20T13:32:12.278528Z"
  },
  {
    "id": 149,
    "title": "python.lang.security.audit.ssrf-requests",
    "description": "User-controlled URL passed to requests.get() without validation. Possible SSRF.",
    "severity": "high",
    "status": "active",
    "cvss_score": null,
    "cwe": 918,
    "cve": null,
    "scanner": "Semgrep",
    "tool_type": "SAST",
    "file_path": "src/integrations/webhook_sender.py",
    "line_number": 56,
    "component": null,
    "component_version": null,
    "is_duplicate": true,
    "mitigation": "",
    "product_id": 4,
    "date_found": "2026-03-20T13:32:12.276970Z",
    "created_at": "2026-03-20T13:32:12.276971Z"
  },
  {
    "id": 148,
    "title": "python.lang.security.audit.insecure-hash",
    "description": "MD5 hash for password storage. MD5 is cryptographically broken; use bcrypt or argon2.",
    "severity": "high",
    "status": "active",
    "cvss_score": null,
    "cwe": 327,
    "cve": null,
    "scanner": "Semgrep",
    "tool_type": "SAST",
    "file_path": "src/auth/password_handler.py",
    "line_number": 34,
    "component": null,
    "component_version": null,
    "is_duplicate": true,
    "mitigation": "",
    "product_id": 4,
    "date_found": "2026-03-20T13:32:12.275694Z",
    "created_at": "2026-03-20T13:32:12.275694Z"
  },
  {
    "id": 147,
    "title": "python.lang.security.deserialization.avoid-pickle",
    "description": "pickle.loads() can lead to arbitrary code execution via deserialization attacks.",
    "severity": "high",
    "status": "active",
    "cvss_score": null,
    "cwe": 502,
    "cve": null,
    "scanner": "Semgrep",
    "tool_type": "SAST",
    "file_path": "src/ml/model_loader.py",
    "line_number": 12,
    "component": null,
    "component_version": null,
    "is_duplicate": true,
    "mitigation": "",
    "product_id": 4,
    "date_found": "2026-03-20T13:32:12.274331Z",
    "created_at": "2026-03-20T13:32:12.274332Z"
  },
  {
    "id": 146,
    "title": "python.lang.security.audit.xss-template",
    "description": "User input rendered without escaping in template enables XSS.",
    "severity": "medium",
    "status": "active",
    "cvss_score": null,
    "cwe": 79,
    "cve": null,
    "scanner": "Semgrep",
    "tool_type": "SAST",
    "file_path": "src/templates/user_profile.html",
    "line_number": 23,
    "component": null,
    "component_version": null,
    "is_duplicate": true,
    "mitigation": "",
    "product_id": 4,
    "date_found": "2026-03-20T13:32:12.273033Z",
    "created_at": "2026-03-20T13:32:12.273035Z"
  },
  {
    "id": 145,
    "title": "python.lang.security.audit.sqli",
    "description": "SQL injection via string concatenation in query. Use parameterized queries.",
    "severity": "high",
    "status": "active",
    "cvss_score": null,
    "cwe": 89,
    "cve": null,
    "scanner": "Semgrep",
    "tool_type": "SAST",
    "file_path": "src/services/user_service.py",
    "line_number": 89,
    "component": null,
    "component_version": null,
    "is_duplicate": true,
    "mitigation": "",
    "product_id": 4,
    "date_found": "2026-03-20T13:32:12.271257Z",
    "created_at": "2026-03-20T13:32:12.271258Z"
  }
]

export const authMe = {
  "id": 1,
  "email": "admin@foxnode.io",
  "username": "admin",
  "full_name": "Admin User",
  "role": "analyst",
  "is_active": true,
  "created_at": "2026-03-20T00:21:15.700100Z"
}

export const dashboardStats = {
  "total_products": 5,
  "total_findings": 164,
  "open_findings": 164,
  "critical_findings": 12,
  "high_findings": 88,
  "medium_findings": 46,
  "low_findings": 17,
  "findings_by_severity": {
    "critical": 12,
    "high": 88,
    "medium": 46,
    "low": 17,
    "info": 1
  },
  "findings_by_status": {
    "active": 164
  },
  "findings_by_scanner": {
    "Semgrep": 56,
    "Trivy": 52,
    "Checkov": 22,
    "ZAP": 17,
    "Gitleaks": 13,
    "Bandit": 4
  },
  "recent_findings": [
    {
      "id": 164,
      "title": "CVE-2023-50495 in ncurses",
      "description": "ncurses before 6.4 allows segfault via crafted terminfo file.",
      "severity": "low",
      "status": "active",
      "cvss_score": null,
      "cwe": null,
      "cve": "CVE-2023-50495",
      "scanner": "Trivy",
      "tool_type": "SCA",
      "file_path": "Dockerfile",
      "line_number": null,
      "component": "ncurses",
      "component_version": "6.3-2",
      "is_duplicate": true,
      "mitigation": "Update to 6.4+20231016",
      "product_id": 5,
      "date_found": "2026-03-20T13:32:12.344258Z",
      "created_at": "2026-03-20T13:32:12.344259Z"
    },
    {
      "id": 163,
      "title": "CVE-2024-2961 in glibc",
      "description": "Buffer overflow in glibc iconv when converting to ISO-2022-CN-EXT character set.",
      "severity": "high",
      "status": "active",
      "cvss_score": null,
      "cwe": null,
      "cve": "CVE-2024-2961",
      "scanner": "Trivy",
      "tool_type": "SCA",
      "file_path": "Dockerfile",
      "line_number": null,
      "component": "glibc",
      "component_version": "2.35",
      "is_duplicate": true,
      "mitigation": "Update to 2.35-0ubuntu3.8",
      "product_id": 5,
      "date_found": "2026-03-20T13:32:12.342603Z",
      "created_at": "2026-03-20T13:32:12.342604Z"
    },
    {
      "id": 162,
      "title": "CVE-2024-32002 in git",
      "description": "Git before 2.39.4 allows remote code execution during recursive clone with crafted submodules.",
      "severity": "critical",
      "status": "active",
      "cvss_score": null,
      "cwe": null,
      "cve": "CVE-2024-32002",
      "scanner": "Trivy",
      "tool_type": "SCA",
      "file_path": "Dockerfile",
      "line_number": null,
      "component": "git",
      "component_version": "2.39.2",
      "is_duplicate": true,
      "mitigation": "Update to 2.39.4",
      "product_id": 5,
      "date_found": "2026-03-20T13:32:12.341216Z",
      "created_at": "2026-03-20T13:32:12.341217Z"
    },
    {
      "id": 161,
      "title": "CVE-2024-21538 in cross-spawn",
      "description": "Cross-spawn before 7.0.5 allows ReDoS via crafted command arguments.",
      "severity": "high",
      "status": "active",
      "cvss_score": null,
      "cwe": null,
      "cve": "CVE-2024-21538",
      "scanner": "Trivy",
      "tool_type": "SCA",
      "file_path": "package-lock.json",
      "line_number": null,
      "component": "cross-spawn",
      "component_version": "7.0.3",
      "is_duplicate": true,
      "mitigation": "Update to 7.0.5",
      "product_id": 5,
      "date_found": "2026-03-20T13:32:12.339722Z",
      "created_at": "2026-03-20T13:32:12.339723Z"
    },
    {
      "id": 160,
      "title": "CVE-2024-37890 in ws",
      "description": "ws before 7.5.10 vulnerable to DoS when Sec-WebSocket-Protocol header has excessive length.",
      "severity": "high",
      "status": "active",
      "cvss_score": null,
      "cwe": null,
      "cve": "CVE-2024-37890",
      "scanner": "Trivy",
      "tool_type": "SCA",
      "file_path": "package-lock.json",
      "line_number": null,
      "component": "ws",
      "component_version": "7.5.9",
      "is_duplicate": true,
      "mitigation": "Update to 7.5.10",
      "product_id": 5,
      "date_found": "2026-03-20T13:32:12.338141Z",
      "created_at": "2026-03-20T13:32:12.338143Z"
    },
    {
      "id": 159,
      "title": "CVE-2023-26159 in follow-redirects",
      "description": "Improper URL handling allows attacks via hostname manipulation.",
      "severity": "medium",
      "status": "active",
      "cvss_score": null,
      "cwe": null,
      "cve": "CVE-2023-26159",
      "scanner": "Trivy",
      "tool_type": "SCA",
      "file_path": "package-lock.json",
      "line_number": null,
      "component": "follow-redirects",
      "component_version": "1.15.2",
      "is_duplicate": true,
      "mitigation": "Update to 1.15.4",
      "product_id": 5,
      "date_found": "2026-03-20T13:32:12.336769Z",
      "created_at": "2026-03-20T13:32:12.336770Z"
    },
    {
      "id": 158,
      "title": "CVE-2024-28849 in follow-redirects",
      "description": "Follow-redirects before 1.15.6 leaks Authorization headers on cross-origin redirect.",
      "severity": "medium",
      "status": "active",
      "cvss_score": null,
      "cwe": null,
      "cve": "CVE-2024-28849",
      "scanner": "Trivy",
      "tool_type": "SCA",
      "file_path": "package-lock.json",
      "line_number": null,
      "component": "follow-redirects",
      "component_version": "1.15.2",
      "is_duplicate": true,
      "mitigation": "Update to 1.15.6",
      "product_id": 5,
      "date_found": "2026-03-20T13:32:12.334976Z",
      "created_at": "2026-03-20T13:32:12.334977Z"
    },
    {
      "id": 157,
      "title": "CVE-2023-44270 in postcss",
      "description": "PostCSS before 8.4.31 misparses external CSS with line returns.",
      "severity": "medium",
      "status": "active",
      "cvss_score": null,
      "cwe": null,
      "cve": "CVE-2023-44270",
      "scanner": "Trivy",
      "tool_type": "SCA",
      "file_path": "package-lock.json",
      "line_number": null,
      "component": "postcss",
      "component_version": "8.4.14",
      "is_duplicate": true,
      "mitigation": "Update to 8.4.31",
      "product_id": 5,
      "date_found": "2026-03-20T13:32:12.333740Z",
      "created_at": "2026-03-20T13:32:12.333741Z"
    },
    {
      "id": 156,
      "title": "CVE-2024-4068 in braces",
      "description": "Braces before 3.0.3 is vulnerable to Regular Expression Denial of Service.",
      "severity": "high",
      "status": "active",
      "cvss_score": null,
      "cwe": null,
      "cve": "CVE-2024-4068",
      "scanner": "Trivy",
      "tool_type": "SCA",
      "file_path": "package-lock.json",
      "line_number": null,
      "component": "braces",
      "component_version": "3.0.2",
      "is_duplicate": true,
      "mitigation": "Update to 3.0.3",
      "product_id": 5,
      "date_found": "2026-03-20T13:32:12.332378Z",
      "created_at": "2026-03-20T13:32:12.332379Z"
    },
    {
      "id": 155,
      "title": "CVE-2024-29041 in express",
      "description": "Express before 4.19.2 allows response splitting via untrusted input in res.location().",
      "severity": "high",
      "status": "active",
      "cvss_score": null,
      "cwe": null,
      "cve": "CVE-2024-29041",
      "scanner": "Trivy",
      "tool_type": "SCA",
      "file_path": "package-lock.json",
      "line_number": null,
      "component": "express",
      "component_version": "4.17.1",
      "is_duplicate": true,
      "mitigation": "Update to 4.19.2",
      "product_id": 5,
      "date_found": "2026-03-20T13:32:12.330838Z",
      "created_at": "2026-03-20T13:32:12.330840Z"
    }
  ],
  "risk_trend": [],
  "top_vulnerable_products": [
    {
      "name": "Customer Portal",
      "count": 47
    },
    {
      "name": "Payment Gateway",
      "count": 38
    },
    {
      "name": "Internal Admin Dashboard",
      "count": 30
    },
    {
      "name": "Infrastructure Platform",
      "count": 25
    },
    {
      "name": "Mobile Banking App",
      "count": 24
    }
  ],
  "mean_time_to_remediate": null
}

export const products = [
  {
    "id": 5,
    "name": "Internal Admin Dashboard",
    "description": "Internal tool for operations team to manage users, configs, and system monitoring",
    "product_type": "web_application",
    "business_criticality": "medium",
    "team": null,
    "risk_score": 0,
    "repo_url": null,
    "created_at": "2026-03-20T08:45:24.091864Z",
    "finding_counts": {
      "low": 2,
      "high": 15,
      "critical": 4,
      "medium": 9
    }
  },
  {
    "id": 4,
    "name": "Mobile Banking App",
    "description": "iOS and Android mobile banking application with biometric auth, transfers, and bill payments",
    "product_type": "mobile",
    "business_criticality": "critical",
    "team": null,
    "risk_score": 0,
    "repo_url": null,
    "created_at": "2026-03-20T08:45:24.063856Z",
    "finding_counts": {
      "low": 1,
      "high": 15,
      "medium": 8
    }
  },
  {
    "id": 3,
    "name": "Infrastructure Platform",
    "description": "Terraform-managed AWS infrastructure including EKS clusters, RDS instances, and networking",
    "product_type": "infrastructure",
    "business_criticality": "critical",
    "team": null,
    "risk_score": 0,
    "repo_url": null,
    "created_at": "2026-03-20T08:45:24.032666Z",
    "finding_counts": {
      "low": 4,
      "high": 11,
      "critical": 3,
      "medium": 7
    }
  },
  {
    "id": 2,
    "name": "Customer Portal",
    "description": "React-based customer-facing web application with authentication, account management, and order tracking",
    "product_type": "web_application",
    "business_criticality": "high",
    "team": null,
    "risk_score": 0,
    "repo_url": null,
    "created_at": "2026-03-20T08:45:23.993655Z",
    "finding_counts": {
      "low": 10,
      "high": 18,
      "info": 1,
      "critical": 5,
      "medium": 13
    }
  },
  {
    "id": 1,
    "name": "Payment Gateway",
    "description": "Core payment processing microservice handling credit card transactions and PCI compliance",
    "product_type": "api",
    "business_criticality": "critical",
    "team": null,
    "risk_score": 0,
    "repo_url": null,
    "created_at": "2026-03-20T08:45:23.952414Z",
    "finding_counts": {
      "high": 29,
      "medium": 9
    }
  }
]

export const findingDetail = {
  "id": 1,
  "title": "python.lang.security.audit.dangerous-subprocess-use",
  "description": "Dangerous subprocess use with user-controlled input. Use shlex.quote() or a safer alternative.",
  "severity": "high",
  "status": "active",
  "cvss_score": null,
  "cwe": 78,
  "cve": null,
  "scanner": "Semgrep",
  "tool_type": "SAST",
  "file_path": "app/services/payment_processor.py",
  "line_number": 45,
  "component": null,
  "component_version": null,
  "is_duplicate": false,
  "mitigation": "",
  "product_id": 1,
  "date_found": "2026-03-20T08:48:46.216376Z",
  "created_at": "2026-03-20T08:48:46.216377Z"
}

export const findingsSummary = {
  "total": 99,
  "by_severity": {
    "low": 11,
    "high": 50,
    "info": 1,
    "critical": 7,
    "medium": 30
  },
  "by_status": {
    "active": 99
  }
}

export const engagements = [
  {
    "id": 27,
    "name": "Mobile App Security Review",
    "description": "OWASP MSTG-based security review of mobile apps",
    "status": "not_started",
    "engagement_type": "security_review",
    "product_id": 4,
    "created_at": "2026-03-20T13:32:12.402979Z"
  },
  {
    "id": 26,
    "name": "Container Security Audit",
    "description": "Security assessment of Docker and Kubernetes configs",
    "status": "not_started",
    "engagement_type": "audit",
    "product_id": 3,
    "created_at": "2026-03-20T13:32:12.392707Z"
  },
  {
    "id": 25,
    "name": "Q1 2026 Penetration Test",
    "description": "Annual pen test covering all external-facing services",
    "status": "not_started",
    "engagement_type": "pentest",
    "product_id": 1,
    "created_at": "2026-03-20T13:32:12.381084Z"
  },
  {
    "id": 24,
    "name": "Auto-import: Trivy",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 5,
    "created_at": "2026-03-20T13:32:12.325754Z"
  },
  {
    "id": 23,
    "name": "Auto-import: Semgrep",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 4,
    "created_at": "2026-03-20T13:32:12.266635Z"
  },
  {
    "id": 22,
    "name": "Auto-import: ZAP",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 2,
    "created_at": "2026-03-20T13:32:12.215336Z"
  },
  {
    "id": 21,
    "name": "Auto-import: Gitleaks",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 1,
    "created_at": "2026-03-20T13:32:12.167573Z"
  },
  {
    "id": 20,
    "name": "Auto-import: Checkov",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 3,
    "created_at": "2026-03-20T13:32:12.114840Z"
  },
  {
    "id": 19,
    "name": "Auto-import: Trivy",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 2,
    "created_at": "2026-03-20T13:32:12.051004Z"
  },
  {
    "id": 18,
    "name": "Auto-import: Semgrep",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 1,
    "created_at": "2026-03-20T13:32:11.979057Z"
  },
  {
    "id": 17,
    "name": "Mobile App Security Review",
    "description": "OWASP MSTG-based security review of iOS and Android apps",
    "status": "not_started",
    "engagement_type": "security_review",
    "product_id": 4,
    "created_at": "2026-03-20T13:20:08.370565Z"
  },
  {
    "id": 16,
    "name": "Container Security Audit",
    "description": "Security assessment of Docker containers and Kubernetes configurations",
    "status": "not_started",
    "engagement_type": "audit",
    "product_id": 3,
    "created_at": "2026-03-20T13:20:08.344527Z"
  },
  {
    "id": 15,
    "name": "Q1 2026 Penetration Test",
    "description": "Annual penetration test covering all external-facing services",
    "status": "not_started",
    "engagement_type": "pentest",
    "product_id": 1,
    "created_at": "2026-03-20T13:20:08.320753Z"
  },
  {
    "id": 14,
    "name": "Auto-import: Trivy",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 5,
    "created_at": "2026-03-20T13:19:52.875789Z"
  },
  {
    "id": 13,
    "name": "Auto-import: Semgrep",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 4,
    "created_at": "2026-03-20T13:19:52.850770Z"
  },
  {
    "id": 12,
    "name": "Auto-import: ZAP",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 2,
    "created_at": "2026-03-20T13:19:52.827294Z"
  },
  {
    "id": 11,
    "name": "Auto-import: Gitleaks",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 1,
    "created_at": "2026-03-20T13:19:52.803670Z"
  },
  {
    "id": 10,
    "name": "Auto-import: Checkov",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 3,
    "created_at": "2026-03-20T13:19:52.779984Z"
  },
  {
    "id": 9,
    "name": "Auto-import: Trivy",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 2,
    "created_at": "2026-03-20T13:19:52.751853Z"
  },
  {
    "id": 8,
    "name": "Auto-import: Semgrep",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 1,
    "created_at": "2026-03-20T13:19:52.718035Z"
  },
  {
    "id": 7,
    "name": "Auto-import: Semgrep",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 5,
    "created_at": "2026-03-20T08:48:46.390914Z"
  },
  {
    "id": 6,
    "name": "Auto-import: Bandit",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 4,
    "created_at": "2026-03-20T08:48:46.360106Z"
  },
  {
    "id": 5,
    "name": "Auto-import: Gitleaks",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 3,
    "created_at": "2026-03-20T08:48:46.330230Z"
  },
  {
    "id": 4,
    "name": "Auto-import: ZAP",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 2,
    "created_at": "2026-03-20T08:48:46.299201Z"
  },
  {
    "id": 3,
    "name": "Auto-import: Checkov",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 3,
    "created_at": "2026-03-20T08:48:46.267682Z"
  },
  {
    "id": 2,
    "name": "Auto-import: Trivy",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 2,
    "created_at": "2026-03-20T08:48:46.237937Z"
  },
  {
    "id": 1,
    "name": "Auto-import: Semgrep",
    "description": null,
    "status": "not_started",
    "engagement_type": "CI/CD",
    "product_id": 1,
    "created_at": "2026-03-20T08:48:46.198765Z"
  }
]

export const integrations = []

export const supportedTools = [
  {
    "name": "Trivy",
    "type": "container",
    "description": "Container and filesystem vulnerability scanner"
  },
  {
    "name": "Semgrep",
    "type": "sast",
    "description": "Lightweight static analysis for many languages"
  },
  {
    "name": "SonarQube",
    "type": "sast",
    "description": "Continuous code quality and security inspection"
  },
  {
    "name": "Snyk",
    "type": "sca",
    "description": "Developer-first security for dependencies"
  },
  {
    "name": "OWASP ZAP",
    "type": "dast",
    "description": "Dynamic application security testing"
  },
  {
    "name": "Nuclei",
    "type": "dast",
    "description": "Fast and customizable vulnerability scanner"
  },
  {
    "name": "Burp Suite",
    "type": "dast",
    "description": "Web security testing toolkit"
  },
  {
    "name": "Checkov",
    "type": "iac",
    "description": "Infrastructure as code static analysis"
  },
  {
    "name": "tfsec",
    "type": "iac",
    "description": "Terraform security scanner"
  },
  {
    "name": "Gitleaks",
    "type": "secret_detection",
    "description": "Secret detection in git repos"
  },
  {
    "name": "TruffleHog",
    "type": "secret_detection",
    "description": "Find leaked credentials"
  },
  {
    "name": "AWS Security Hub",
    "type": "cloud",
    "description": "AWS cloud security posture"
  },
  {
    "name": "Prowler",
    "type": "cloud",
    "description": "AWS/Azure/GCP security assessments"
  },
  {
    "name": "ScoutSuite",
    "type": "cloud",
    "description": "Multi-cloud security auditing"
  },
  {
    "name": "Nmap",
    "type": "infrastructure",
    "description": "Network discovery and security auditing"
  },
  {
    "name": "OpenVAS",
    "type": "infrastructure",
    "description": "Open vulnerability assessment scanner"
  },
  {
    "name": "Qualys",
    "type": "infrastructure",
    "description": "Enterprise vulnerability management"
  },
  {
    "name": "Dependency-Check",
    "type": "sca",
    "description": "OWASP dependency vulnerability detection"
  },
  {
    "name": "Bandit",
    "type": "sast",
    "description": "Python code security analysis"
  },
  {
    "name": "ESLint Security",
    "type": "sast",
    "description": "JavaScript security linting rules"
  },
  {
    "name": "Jira",
    "type": "issue_tracker",
    "description": "Issue and project tracking"
  },
  {
    "name": "GitHub Issues",
    "type": "issue_tracker",
    "description": "GitHub issue tracking"
  },
  {
    "name": "Slack",
    "type": "notification",
    "description": "Team messaging and alerts"
  },
  {
    "name": "PagerDuty",
    "type": "notification",
    "description": "Incident management"
  }
]

export const scanParsers = [
  {
    "name": "Trivy",
    "scan_type": "SCA",
    "description": "Trivy container and filesystem vulnerability scanner"
  },
  {
    "name": "Semgrep",
    "scan_type": "SAST",
    "description": "Semgrep static analysis findings"
  },
  {
    "name": "Snyk",
    "scan_type": "SCA",
    "description": "Snyk dependency vulnerability scanner"
  },
  {
    "name": "Gitleaks",
    "scan_type": "Secret Detection",
    "description": "Gitleaks secret detection scanner"
  },
  {
    "name": "Bandit",
    "scan_type": "SAST",
    "description": "Bandit Python security linter"
  },
  {
    "name": "ZAP",
    "scan_type": "DAST",
    "description": "OWASP ZAP dynamic security scanner"
  },
  {
    "name": "Nuclei",
    "scan_type": "DAST",
    "description": "Nuclei vulnerability scanner"
  },
  {
    "name": "Generic",
    "scan_type": "Generic",
    "description": "Generic CSV/JSON import format for any scanner"
  },
  {
    "name": "Checkov",
    "scan_type": "IaC",
    "description": "Checkov Infrastructure-as-Code security scanner"
  },
  {
    "name": "SonarQube",
    "scan_type": "SAST",
    "description": "SonarQube static analysis scanner"
  },
  {
    "name": "DependencyCheck",
    "scan_type": "SCA",
    "description": "OWASP Dependency-Check vulnerability scanner"
  },
  {
    "name": "Prowler",
    "scan_type": "Cloud Security",
    "description": "Prowler AWS/Azure/GCP cloud security scanner"
  },
  {
    "name": "tfsec",
    "scan_type": "IaC",
    "description": "tfsec Terraform security scanner"
  },
  {
    "name": "TruffleHog",
    "scan_type": "Secret Detection",
    "description": "TruffleHog secret and credential detector"
  },
  {
    "name": "SARIF",
    "scan_type": "SAST",
    "description": "SARIF (Static Analysis Results Interchange Format) universal parser"
  }
]

export const scanHistory = [
  {
    "id": 21,
    "filename": "trivy-results.json",
    "scanner": "Trivy",
    "status": "completed",
    "findings_created": 0,
    "findings_duplicates": 11,
    "created_at": "2026-03-20T13:32:12.326662Z"
  },
  {
    "id": 20,
    "filename": "semgrep-results.json",
    "scanner": "Semgrep",
    "status": "completed",
    "findings_created": 0,
    "findings_duplicates": 10,
    "created_at": "2026-03-20T13:32:12.267665Z"
  },
  {
    "id": 19,
    "filename": "zap-results.json",
    "scanner": "ZAP",
    "status": "completed",
    "findings_created": 0,
    "findings_duplicates": 6,
    "created_at": "2026-03-20T13:32:12.216048Z"
  },
  {
    "id": 18,
    "filename": "gitleaks-results.json",
    "scanner": "Gitleaks",
    "status": "completed",
    "findings_created": 0,
    "findings_duplicates": 5,
    "created_at": "2026-03-20T13:32:12.168408Z"
  },
  {
    "id": 17,
    "filename": "checkov-results.json",
    "scanner": "Checkov",
    "status": "completed",
    "findings_created": 0,
    "findings_duplicates": 8,
    "created_at": "2026-03-20T13:32:12.115489Z"
  },
  {
    "id": 16,
    "filename": "trivy-results.json",
    "scanner": "Trivy",
    "status": "completed",
    "findings_created": 0,
    "findings_duplicates": 11,
    "created_at": "2026-03-20T13:32:12.056224Z"
  },
  {
    "id": 15,
    "filename": "semgrep-results.json",
    "scanner": "Semgrep",
    "status": "completed",
    "findings_created": 0,
    "findings_duplicates": 10,
    "created_at": "2026-03-20T13:32:11.984153Z"
  },
  {
    "id": 14,
    "filename": "trivy-results.json",
    "scanner": "Trivy",
    "status": "completed",
    "findings_created": 11,
    "findings_duplicates": 0,
    "created_at": "2026-03-20T13:19:52.876462Z"
  },
  {
    "id": 13,
    "filename": "semgrep-results.json",
    "scanner": "Semgrep",
    "status": "completed",
    "findings_created": 10,
    "findings_duplicates": 0,
    "created_at": "2026-03-20T13:19:52.851481Z"
  },
  {
    "id": 12,
    "filename": "zap-results.json",
    "scanner": "ZAP",
    "status": "completed",
    "findings_created": 6,
    "findings_duplicates": 0,
    "created_at": "2026-03-20T13:19:52.829084Z"
  },
  {
    "id": 11,
    "filename": "gitleaks-results.json",
    "scanner": "Gitleaks",
    "status": "completed",
    "findings_created": 5,
    "findings_duplicates": 0,
    "created_at": "2026-03-20T13:19:52.811603Z"
  },
  {
    "id": 10,
    "filename": "checkov-results.json",
    "scanner": "Checkov",
    "status": "completed",
    "findings_created": 8,
    "findings_duplicates": 0,
    "created_at": "2026-03-20T13:19:52.782615Z"
  },
  {
    "id": 9,
    "filename": "trivy-results.json",
    "scanner": "Trivy",
    "status": "completed",
    "findings_created": 7,
    "findings_duplicates": 4,
    "created_at": "2026-03-20T13:19:52.755111Z"
  },
  {
    "id": 8,
    "filename": "semgrep-results.json",
    "scanner": "Semgrep",
    "status": "completed",
    "findings_created": 10,
    "findings_duplicates": 0,
    "created_at": "2026-03-20T13:19:52.726252Z"
  },
  {
    "id": 7,
    "filename": "semgrep-results.json",
    "scanner": "Semgrep",
    "status": "completed",
    "findings_created": 8,
    "findings_duplicates": 0,
    "created_at": "2026-03-20T08:48:46.391739Z"
  },
  {
    "id": 6,
    "filename": "bandit-results.json",
    "scanner": "Bandit",
    "status": "completed",
    "findings_created": 4,
    "findings_duplicates": 0,
    "created_at": "2026-03-20T08:48:46.360719Z"
  },
  {
    "id": 5,
    "filename": "gitleaks-results.json",
    "scanner": "Gitleaks",
    "status": "completed",
    "findings_created": 3,
    "findings_duplicates": 0,
    "created_at": "2026-03-20T08:48:46.332378Z"
  },
  {
    "id": 4,
    "filename": "zap-results.json",
    "scanner": "ZAP",
    "status": "completed",
    "findings_created": 5,
    "findings_duplicates": 0,
    "created_at": "2026-03-20T08:48:46.305263Z"
  },
  {
    "id": 3,
    "filename": "checkov-results.json",
    "scanner": "Checkov",
    "status": "completed",
    "findings_created": 6,
    "findings_duplicates": 0,
    "created_at": "2026-03-20T08:48:46.274892Z"
  },
  {
    "id": 2,
    "filename": "trivy-results.json",
    "scanner": "Trivy",
    "status": "completed",
    "findings_created": 8,
    "findings_duplicates": 0,
    "created_at": "2026-03-20T08:48:46.240630Z"
  },
  {
    "id": 1,
    "filename": "semgrep-results.json",
    "scanner": "Semgrep",
    "status": "completed",
    "findings_created": 8,
    "findings_duplicates": 0,
    "created_at": "2026-03-20T08:48:46.207853Z"
  }
]

export const scorecardOverview = {
  "org_score": 84.8,
  "org_grade": "B",
  "org_trend": "improving",
  "total_products": 5,
  "product_scores": [
    {
      "product_id": 2,
      "product_name": "Customer Portal",
      "business_criticality": "high",
      "score": 82.8,
      "grade": "B",
      "trend": "improving",
      "open_findings": 26,
      "recommendations": [
        "Prioritize 3 critical finding(s) for immediate remediation.",
        "Reduce the 7 open high-severity findings to lower risk exposure.",
        "No remediated findings yet. Begin tracking remediation timelines.",
        "Only 0.0% of findings are mitigated. Increase remediation efforts."
      ]
    },
    {
      "product_id": 3,
      "product_name": "Infrastructure Platform",
      "business_criticality": "critical",
      "score": 86.1,
      "grade": "B",
      "trend": "stable",
      "open_findings": 17,
      "recommendations": [
        "Prioritize 2 critical finding(s) for immediate remediation.",
        "Reduce the 8 open high-severity findings to lower risk exposure.",
        "No remediated findings yet. Begin tracking remediation timelines.",
        "Only 0.0% of findings are mitigated. Increase remediation efforts."
      ]
    },
    {
      "product_id": 5,
      "product_name": "Internal Admin Dashboard",
      "business_criticality": "medium",
      "score": 83.5,
      "grade": "B",
      "trend": "improving",
      "open_findings": 19,
      "recommendations": [
        "Prioritize 2 critical finding(s) for immediate remediation.",
        "Reduce the 10 open high-severity findings to lower risk exposure.",
        "No remediated findings yet. Begin tracking remediation timelines.",
        "Only 0.0% of findings are mitigated. Increase remediation efforts."
      ]
    },
    {
      "product_id": 4,
      "product_name": "Mobile Banking App",
      "business_criticality": "critical",
      "score": 89.9,
      "grade": "B",
      "trend": "stable",
      "open_findings": 14,
      "recommendations": [
        "Reduce the 8 open high-severity findings to lower risk exposure.",
        "No remediated findings yet. Begin tracking remediation timelines.",
        "Only 0.0% of findings are mitigated. Increase remediation efforts."
      ]
    },
    {
      "product_id": 1,
      "product_name": "Payment Gateway",
      "business_criticality": "critical",
      "score": 80.6,
      "grade": "B",
      "trend": "improving",
      "open_findings": 23,
      "recommendations": [
        "Reduce the 17 open high-severity findings to lower risk exposure.",
        "No remediated findings yet. Begin tracking remediation timelines.",
        "Only 0.0% of findings are mitigated. Increase remediation efforts."
      ]
    }
  ],
  "leaderboard": [
    {
      "product_id": 4,
      "product_name": "Mobile Banking App",
      "business_criticality": "critical",
      "score": 89.9,
      "grade": "B",
      "trend": "stable",
      "open_findings": 14,
      "recommendations": [
        "Reduce the 8 open high-severity findings to lower risk exposure.",
        "No remediated findings yet. Begin tracking remediation timelines.",
        "Only 0.0% of findings are mitigated. Increase remediation efforts."
      ]
    },
    {
      "product_id": 3,
      "product_name": "Infrastructure Platform",
      "business_criticality": "critical",
      "score": 86.1,
      "grade": "B",
      "trend": "stable",
      "open_findings": 17,
      "recommendations": [
        "Prioritize 2 critical finding(s) for immediate remediation.",
        "Reduce the 8 open high-severity findings to lower risk exposure.",
        "No remediated findings yet. Begin tracking remediation timelines.",
        "Only 0.0% of findings are mitigated. Increase remediation efforts."
      ]
    },
    {
      "product_id": 5,
      "product_name": "Internal Admin Dashboard",
      "business_criticality": "medium",
      "score": 83.5,
      "grade": "B",
      "trend": "improving",
      "open_findings": 19,
      "recommendations": [
        "Prioritize 2 critical finding(s) for immediate remediation.",
        "Reduce the 10 open high-severity findings to lower risk exposure.",
        "No remediated findings yet. Begin tracking remediation timelines.",
        "Only 0.0% of findings are mitigated. Increase remediation efforts."
      ]
    },
    {
      "product_id": 2,
      "product_name": "Customer Portal",
      "business_criticality": "high",
      "score": 82.8,
      "grade": "B",
      "trend": "improving",
      "open_findings": 26,
      "recommendations": [
        "Prioritize 3 critical finding(s) for immediate remediation.",
        "Reduce the 7 open high-severity findings to lower risk exposure.",
        "No remediated findings yet. Begin tracking remediation timelines.",
        "Only 0.0% of findings are mitigated. Increase remediation efforts."
      ]
    },
    {
      "product_id": 1,
      "product_name": "Payment Gateway",
      "business_criticality": "critical",
      "score": 80.6,
      "grade": "B",
      "trend": "improving",
      "open_findings": 23,
      "recommendations": [
        "Reduce the 17 open high-severity findings to lower risk exposure.",
        "No remediated findings yet. Begin tracking remediation timelines.",
        "Only 0.0% of findings are mitigated. Increase remediation efforts."
      ]
    }
  ],
  "history": [
    {
      "date": "2026-02-20",
      "score": 80.5,
      "grade": "B"
    },
    {
      "date": "2026-02-21",
      "score": 79.3,
      "grade": "C"
    },
    {
      "date": "2026-02-22",
      "score": 81.3,
      "grade": "B"
    },
    {
      "date": "2026-02-23",
      "score": 80.5,
      "grade": "B"
    },
    {
      "date": "2026-02-24",
      "score": 82.5,
      "grade": "B"
    },
    {
      "date": "2026-02-25",
      "score": 83.9,
      "grade": "B"
    },
    {
      "date": "2026-02-26",
      "score": 85.3,
      "grade": "B"
    },
    {
      "date": "2026-02-27",
      "score": 84.1,
      "grade": "B"
    },
    {
      "date": "2026-02-28",
      "score": 82.2,
      "grade": "B"
    },
    {
      "date": "2026-03-01",
      "score": 80.5,
      "grade": "B"
    },
    {
      "date": "2026-03-02",
      "score": 81.1,
      "grade": "B"
    },
    {
      "date": "2026-03-03",
      "score": 81.3,
      "grade": "B"
    },
    {
      "date": "2026-03-04",
      "score": 80.8,
      "grade": "B"
    },
    {
      "date": "2026-03-05",
      "score": 79.1,
      "grade": "C"
    },
    {
      "date": "2026-03-06",
      "score": 81.2,
      "grade": "B"
    },
    {
      "date": "2026-03-07",
      "score": 81.6,
      "grade": "B"
    },
    {
      "date": "2026-03-08",
      "score": 80.6,
      "grade": "B"
    },
    {
      "date": "2026-03-09",
      "score": 79.8,
      "grade": "C"
    },
    {
      "date": "2026-03-10",
      "score": 81.9,
      "grade": "B"
    },
    {
      "date": "2026-03-11",
      "score": 84.2,
      "grade": "B"
    },
    {
      "date": "2026-03-12",
      "score": 86,
      "grade": "B"
    },
    {
      "date": "2026-03-13",
      "score": 86.4,
      "grade": "B"
    },
    {
      "date": "2026-03-14",
      "score": 87.2,
      "grade": "B"
    },
    {
      "date": "2026-03-15",
      "score": 88.9,
      "grade": "B"
    },
    {
      "date": "2026-03-16",
      "score": 87.8,
      "grade": "B"
    },
    {
      "date": "2026-03-17",
      "score": 87.9,
      "grade": "B"
    },
    {
      "date": "2026-03-18",
      "score": 86,
      "grade": "B"
    },
    {
      "date": "2026-03-19",
      "score": 86.1,
      "grade": "B"
    },
    {
      "date": "2026-03-20",
      "score": 88.2,
      "grade": "B"
    },
    {
      "date": "2026-03-21",
      "score": 84.8,
      "grade": "B"
    }
  ]
}

export const scorecardTrends = {
  "product_id": null,
  "data_points": [
    {
      "date": "2026-02-20",
      "score": 80.5,
      "grade": "B"
    },
    {
      "date": "2026-02-21",
      "score": 79.3,
      "grade": "C"
    },
    {
      "date": "2026-02-22",
      "score": 81.3,
      "grade": "B"
    },
    {
      "date": "2026-02-23",
      "score": 80.5,
      "grade": "B"
    },
    {
      "date": "2026-02-24",
      "score": 82.5,
      "grade": "B"
    },
    {
      "date": "2026-02-25",
      "score": 83.9,
      "grade": "B"
    },
    {
      "date": "2026-02-26",
      "score": 85.3,
      "grade": "B"
    },
    {
      "date": "2026-02-27",
      "score": 84.1,
      "grade": "B"
    },
    {
      "date": "2026-02-28",
      "score": 82.2,
      "grade": "B"
    },
    {
      "date": "2026-03-01",
      "score": 80.5,
      "grade": "B"
    },
    {
      "date": "2026-03-02",
      "score": 81.1,
      "grade": "B"
    },
    {
      "date": "2026-03-03",
      "score": 81.3,
      "grade": "B"
    },
    {
      "date": "2026-03-04",
      "score": 80.8,
      "grade": "B"
    },
    {
      "date": "2026-03-05",
      "score": 79.1,
      "grade": "C"
    },
    {
      "date": "2026-03-06",
      "score": 81.2,
      "grade": "B"
    },
    {
      "date": "2026-03-07",
      "score": 81.6,
      "grade": "B"
    },
    {
      "date": "2026-03-08",
      "score": 80.6,
      "grade": "B"
    },
    {
      "date": "2026-03-09",
      "score": 79.8,
      "grade": "C"
    },
    {
      "date": "2026-03-10",
      "score": 81.9,
      "grade": "B"
    },
    {
      "date": "2026-03-11",
      "score": 84.2,
      "grade": "B"
    },
    {
      "date": "2026-03-12",
      "score": 86,
      "grade": "B"
    },
    {
      "date": "2026-03-13",
      "score": 86.4,
      "grade": "B"
    },
    {
      "date": "2026-03-14",
      "score": 87.2,
      "grade": "B"
    },
    {
      "date": "2026-03-15",
      "score": 88.9,
      "grade": "B"
    },
    {
      "date": "2026-03-16",
      "score": 87.8,
      "grade": "B"
    },
    {
      "date": "2026-03-17",
      "score": 87.9,
      "grade": "B"
    },
    {
      "date": "2026-03-18",
      "score": 86,
      "grade": "B"
    },
    {
      "date": "2026-03-19",
      "score": 86.1,
      "grade": "B"
    },
    {
      "date": "2026-03-20",
      "score": 88.2,
      "grade": "B"
    },
    {
      "date": "2026-03-21",
      "score": 84.8,
      "grade": "B"
    }
  ]
}

export const scorecardProduct = {
  "product_id": 1,
  "score": 80.6,
  "grade": "B",
  "trend": "improving",
  "breakdown": {
    "open_findings_by_severity": {
      "high": 17,
      "medium": 6
    },
    "findings_by_status": {
      "active": 23
    },
    "density_penalty": 19.4,
    "mttr_days": null,
    "mttr_bonus": 0,
    "false_positive_ratio": 0,
    "mitigated_percentage": 0,
    "mitigation_bonus": 0,
    "loc_estimate": 50000
  },
  "recommendations": [
    "Reduce the 17 open high-severity findings to lower risk exposure.",
    "No remediated findings yet. Begin tracking remediation timelines.",
    "Only 0.0% of findings are mitigated. Increase remediation efforts."
  ],
  "history": [
    {
      "date": "2026-02-20",
      "score": 69.5,
      "grade": "D"
    },
    {
      "date": "2026-02-21",
      "score": 70.1,
      "grade": "C"
    },
    {
      "date": "2026-02-22",
      "score": 69.2,
      "grade": "D"
    },
    {
      "date": "2026-02-23",
      "score": 70.3,
      "grade": "C"
    },
    {
      "date": "2026-02-24",
      "score": 71.6,
      "grade": "C"
    },
    {
      "date": "2026-02-25",
      "score": 71.7,
      "grade": "C"
    },
    {
      "date": "2026-02-26",
      "score": 72.9,
      "grade": "C"
    },
    {
      "date": "2026-02-27",
      "score": 71.5,
      "grade": "C"
    },
    {
      "date": "2026-02-28",
      "score": 70.4,
      "grade": "C"
    },
    {
      "date": "2026-03-01",
      "score": 69.3,
      "grade": "D"
    },
    {
      "date": "2026-03-02",
      "score": 71.8,
      "grade": "C"
    },
    {
      "date": "2026-03-03",
      "score": 70.6,
      "grade": "C"
    },
    {
      "date": "2026-03-04",
      "score": 73,
      "grade": "C"
    },
    {
      "date": "2026-03-05",
      "score": 75.5,
      "grade": "C"
    },
    {
      "date": "2026-03-06",
      "score": 73.8,
      "grade": "C"
    },
    {
      "date": "2026-03-07",
      "score": 74,
      "grade": "C"
    },
    {
      "date": "2026-03-08",
      "score": 73.8,
      "grade": "C"
    },
    {
      "date": "2026-03-09",
      "score": 73.3,
      "grade": "C"
    },
    {
      "date": "2026-03-10",
      "score": 73.9,
      "grade": "C"
    },
    {
      "date": "2026-03-11",
      "score": 75.8,
      "grade": "C"
    },
    {
      "date": "2026-03-12",
      "score": 73.9,
      "grade": "C"
    },
    {
      "date": "2026-03-13",
      "score": 72.9,
      "grade": "C"
    },
    {
      "date": "2026-03-14",
      "score": 73.2,
      "grade": "C"
    },
    {
      "date": "2026-03-15",
      "score": 73.5,
      "grade": "C"
    },
    {
      "date": "2026-03-16",
      "score": 73.4,
      "grade": "C"
    },
    {
      "date": "2026-03-17",
      "score": 74.7,
      "grade": "C"
    },
    {
      "date": "2026-03-18",
      "score": 76,
      "grade": "C"
    },
    {
      "date": "2026-03-19",
      "score": 77.5,
      "grade": "C"
    },
    {
      "date": "2026-03-20",
      "score": 76.3,
      "grade": "C"
    },
    {
      "date": "2026-03-21",
      "score": 80.6,
      "grade": "B"
    }
  ],
  "product_name": "Payment Gateway"
}

export const triageSummary = {
  "product_id": 1,
  "total_findings": 38,
  "counts_by_priority": {
    "next_sprint": 5,
    "backlog": 18,
    "monitor": 15
  },
  "top_false_positive_candidates": [],
  "grouped_findings": {
    "CWE-287": [
      52,
      113
    ],
    "CWE-327": [
      47,
      4,
      108
    ],
    "CWE-78": [
      43,
      1,
      104
    ],
    "CWE-89": [
      3,
      44,
      105
    ],
    "path:.github/scripts": [
      75,
      136
    ],
    "path:deploy/ssl": [
      74,
      135
    ],
    "path:src/integrations": [
      73,
      134
    ],
    "path:src/config": [
      72,
      133
    ],
    "CWE-22": [
      50,
      111
    ],
    "CWE-918": [
      48,
      109
    ],
    "CWE-502": [
      46,
      7,
      107
    ],
    "CWE-798": [
      5
    ],
    "CWE-95": [
      2
    ],
    "CWE-352": [
      51,
      112
    ],
    "CWE-601": [
      49,
      110
    ],
    "CWE-79": [
      45,
      6,
      106
    ],
    "CWE-319": [
      8
    ]
  }
}

export const complianceFrameworks = [
  {
    "framework_id": "owasp-top10-2021",
    "name": "OWASP Top 10",
    "version": "2021",
    "description": "OWASP Top 10 Web Application Security Risks (2021 edition)",
    "total_controls": 10
  },
  {
    "framework_id": "cis-benchmarks",
    "name": "CIS Benchmarks",
    "version": "1.0",
    "description": "Center for Internet Security benchmarks for secure configuration of infrastructure and cloud environments.",
    "total_controls": 10
  },
  {
    "framework_id": "pci-dss-v4",
    "name": "PCI-DSS",
    "version": "4.0",
    "description": "Payment Card Industry Data Security Standard version 4.0.",
    "total_controls": 14
  },
  {
    "framework_id": "soc2",
    "name": "SOC 2",
    "version": "2017",
    "description": "Service Organization Control 2 — Trust Services Criteria.",
    "total_controls": 10
  },
  {
    "framework_id": "iso-27001",
    "name": "ISO 27001",
    "version": "2022",
    "description": "ISO/IEC 27001 Information Security Management System (Annex A controls).",
    "total_controls": 11
  }
]

export const complianceOverview = [
  {
    "framework_id": "owasp-top10-2021",
    "framework_name": "OWASP Top 10",
    "version": "2021",
    "compliance_percentage": 20,
    "total_controls": 10,
    "passing_controls": 2,
    "failing_controls": 8,
    "mapped_findings_count": 77
  },
  {
    "framework_id": "cis-benchmarks",
    "framework_name": "CIS Benchmarks",
    "version": "1.0",
    "compliance_percentage": 100,
    "total_controls": 10,
    "passing_controls": 10,
    "failing_controls": 0,
    "mapped_findings_count": 0
  },
  {
    "framework_id": "pci-dss-v4",
    "framework_name": "PCI-DSS",
    "version": "4.0",
    "compliance_percentage": 57.14,
    "total_controls": 14,
    "passing_controls": 8,
    "failing_controls": 6,
    "mapped_findings_count": 77
  },
  {
    "framework_id": "soc2",
    "framework_name": "SOC 2",
    "version": "2017",
    "compliance_percentage": 90,
    "total_controls": 10,
    "passing_controls": 9,
    "failing_controls": 1,
    "mapped_findings_count": 4
  },
  {
    "framework_id": "iso-27001",
    "framework_name": "ISO 27001",
    "version": "2022",
    "compliance_percentage": 54.55,
    "total_controls": 11,
    "passing_controls": 6,
    "failing_controls": 5,
    "mapped_findings_count": 77
  }
]

export const slaStatus = {
  "total_findings": 99,
  "in_sla": 99,
  "breached": 0,
  "breach_rate": 0,
  "by_severity": {
    "critical": {
      "total": 7,
      "in_sla": 7,
      "breached": 0,
      "breach_rate": 0
    },
    "high": {
      "total": 50,
      "in_sla": 50,
      "breached": 0,
      "breach_rate": 0
    },
    "medium": {
      "total": 30,
      "in_sla": 30,
      "breached": 0,
      "breach_rate": 0
    },
    "low": {
      "total": 11,
      "in_sla": 11,
      "breached": 0,
      "breach_rate": 0
    },
    "info": {
      "total": 1,
      "in_sla": 1,
      "breached": 0,
      "breach_rate": 0
    }
  }
}

export const slaBreaches = []

export const slaHeatmap = [
  {
    "product_id": 2,
    "product_name": "Customer Portal",
    "severity": "critical",
    "count": 3,
    "breached_count": 0,
    "risk_level": "high"
  },
  {
    "product_id": 2,
    "product_name": "Customer Portal",
    "severity": "high",
    "count": 7,
    "breached_count": 0,
    "risk_level": "high"
  },
  {
    "product_id": 2,
    "product_name": "Customer Portal",
    "severity": "medium",
    "count": 9,
    "breached_count": 0,
    "risk_level": "medium"
  },
  {
    "product_id": 2,
    "product_name": "Customer Portal",
    "severity": "low",
    "count": 6,
    "breached_count": 0,
    "risk_level": "medium"
  },
  {
    "product_id": 2,
    "product_name": "Customer Portal",
    "severity": "info",
    "count": 1,
    "breached_count": 0,
    "risk_level": "low"
  },
  {
    "product_id": 3,
    "product_name": "Infrastructure Platform",
    "severity": "critical",
    "count": 2,
    "breached_count": 0,
    "risk_level": "high"
  },
  {
    "product_id": 3,
    "product_name": "Infrastructure Platform",
    "severity": "high",
    "count": 8,
    "breached_count": 0,
    "risk_level": "high"
  },
  {
    "product_id": 3,
    "product_name": "Infrastructure Platform",
    "severity": "medium",
    "count": 4,
    "breached_count": 0,
    "risk_level": "medium"
  },
  {
    "product_id": 3,
    "product_name": "Infrastructure Platform",
    "severity": "low",
    "count": 3,
    "breached_count": 0,
    "risk_level": "low"
  },
  {
    "product_id": 3,
    "product_name": "Infrastructure Platform",
    "severity": "info",
    "count": 0,
    "breached_count": 0,
    "risk_level": "low"
  },
  {
    "product_id": 5,
    "product_name": "Internal Admin Dashboard",
    "severity": "critical",
    "count": 2,
    "breached_count": 0,
    "risk_level": "high"
  },
  {
    "product_id": 5,
    "product_name": "Internal Admin Dashboard",
    "severity": "high",
    "count": 10,
    "breached_count": 0,
    "risk_level": "high"
  },
  {
    "product_id": 5,
    "product_name": "Internal Admin Dashboard",
    "severity": "medium",
    "count": 6,
    "breached_count": 0,
    "risk_level": "medium"
  },
  {
    "product_id": 5,
    "product_name": "Internal Admin Dashboard",
    "severity": "low",
    "count": 1,
    "breached_count": 0,
    "risk_level": "low"
  },
  {
    "product_id": 5,
    "product_name": "Internal Admin Dashboard",
    "severity": "info",
    "count": 0,
    "breached_count": 0,
    "risk_level": "low"
  },
  {
    "product_id": 4,
    "product_name": "Mobile Banking App",
    "severity": "critical",
    "count": 0,
    "breached_count": 0,
    "risk_level": "low"
  },
  {
    "product_id": 4,
    "product_name": "Mobile Banking App",
    "severity": "high",
    "count": 8,
    "breached_count": 0,
    "risk_level": "high"
  },
  {
    "product_id": 4,
    "product_name": "Mobile Banking App",
    "severity": "medium",
    "count": 5,
    "breached_count": 0,
    "risk_level": "medium"
  },
  {
    "product_id": 4,
    "product_name": "Mobile Banking App",
    "severity": "low",
    "count": 1,
    "breached_count": 0,
    "risk_level": "low"
  },
  {
    "product_id": 4,
    "product_name": "Mobile Banking App",
    "severity": "info",
    "count": 0,
    "breached_count": 0,
    "risk_level": "low"
  },
  {
    "product_id": 1,
    "product_name": "Payment Gateway",
    "severity": "critical",
    "count": 0,
    "breached_count": 0,
    "risk_level": "low"
  },
  {
    "product_id": 1,
    "product_name": "Payment Gateway",
    "severity": "high",
    "count": 17,
    "breached_count": 0,
    "risk_level": "high"
  },
  {
    "product_id": 1,
    "product_name": "Payment Gateway",
    "severity": "medium",
    "count": 6,
    "breached_count": 0,
    "risk_level": "medium"
  },
  {
    "product_id": 1,
    "product_name": "Payment Gateway",
    "severity": "low",
    "count": 0,
    "breached_count": 0,
    "risk_level": "low"
  },
  {
    "product_id": 1,
    "product_name": "Payment Gateway",
    "severity": "info",
    "count": 0,
    "breached_count": 0,
    "risk_level": "low"
  }
]

export const slaConfig = {
  "targets": {
    "critical": 48,
    "high": 168,
    "medium": 720,
    "low": 2160,
    "info": null
  }
}

export const slaProduct = {
  "product_id": 1,
  "product_name": "Payment Gateway",
  "total_findings": 23,
  "total_in_sla": 23,
  "total_breached": 0,
  "breach_rate": 0,
  "avg_time_to_remediate_hours": null,
  "by_severity": {
    "critical": {
      "total": 0,
      "in_sla": 0,
      "breached": 0,
      "breach_rate": 0
    },
    "high": {
      "total": 17,
      "in_sla": 17,
      "breached": 0,
      "breach_rate": 0
    },
    "medium": {
      "total": 6,
      "in_sla": 6,
      "breached": 0,
      "breach_rate": 0
    },
    "low": {
      "total": 0,
      "in_sla": 0,
      "breached": 0,
      "breach_rate": 0
    },
    "info": {
      "total": 0,
      "in_sla": 0,
      "breached": 0,
      "breach_rate": 0
    }
  }
}

export const metricsKpi = {
  "executive_summary": {
    "overall_risk_level": "critical",
    "risk_trend": "stable",
    "key_metrics": {
      "total_open": 99,
      "critical_open": 7,
      "high_open": 50,
      "mttr_critical_hours": null,
      "sla_compliance_rate": 100,
      "findings_last_7d": 99,
      "resolved_last_7d": 0
    },
    "highlights": [
      "7 critical finding(s) require immediate attention.",
      "99 new finding(s) discovered in the past 7 days."
    ],
    "action_items": [
      "Remediate 7 critical finding(s) within SLA deadlines.",
      "Address 50 high-severity open findings to reduce risk exposure."
    ]
  },
  "mttr": {
    "overall_mttr_hours": null,
    "by_severity": {
      "critical": null,
      "high": null,
      "medium": null,
      "low": null
    },
    "resolved_count": 0,
    "trend_30d": [
      {
        "date": "2026-02-20",
        "value": 58.41
      },
      {
        "date": "2026-02-21",
        "value": 59.46
      },
      {
        "date": "2026-02-22",
        "value": 62.71
      },
      {
        "date": "2026-02-23",
        "value": 61.35
      },
      {
        "date": "2026-02-24",
        "value": 57.11
      },
      {
        "date": "2026-02-25",
        "value": 57.24
      },
      {
        "date": "2026-02-26",
        "value": 63.15
      },
      {
        "date": "2026-02-27",
        "value": 59.71
      },
      {
        "date": "2026-02-28",
        "value": 54.53
      },
      {
        "date": "2026-03-01",
        "value": 53.41
      },
      {
        "date": "2026-03-02",
        "value": 60.06
      },
      {
        "date": "2026-03-03",
        "value": 58.31
      },
      {
        "date": "2026-03-04",
        "value": 57.9
      },
      {
        "date": "2026-03-05",
        "value": 50.69
      },
      {
        "date": "2026-03-06",
        "value": 50.52
      },
      {
        "date": "2026-03-07",
        "value": 56.24
      },
      {
        "date": "2026-03-08",
        "value": 52.97
      },
      {
        "date": "2026-03-09",
        "value": 51.74
      },
      {
        "date": "2026-03-10",
        "value": 48.84
      },
      {
        "date": "2026-03-11",
        "value": 54.6
      },
      {
        "date": "2026-03-12",
        "value": 52.81
      },
      {
        "date": "2026-03-13",
        "value": 55.53
      },
      {
        "date": "2026-03-14",
        "value": 51.73
      },
      {
        "date": "2026-03-15",
        "value": 50.07
      },
      {
        "date": "2026-03-16",
        "value": 52.41
      },
      {
        "date": "2026-03-17",
        "value": 45.09
      },
      {
        "date": "2026-03-18",
        "value": 44.83
      },
      {
        "date": "2026-03-19",
        "value": 52.84
      },
      {
        "date": "2026-03-20",
        "value": 44.46
      },
      {
        "date": "2026-03-21",
        "value": 48
      }
    ]
  },
  "finding_aging": {
    "buckets": {
      "0-7d": {
        "critical": 7,
        "high": 50,
        "medium": 30,
        "low": 11
      },
      "7-30d": {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
      },
      "30-90d": {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
      },
      "90-180d": {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
      },
      "180d+": {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
      }
    },
    "total_by_bucket": {
      "0-7d": 98,
      "7-30d": 0,
      "30-90d": 0,
      "90-180d": 0,
      "180d+": 0
    },
    "total_open": 99,
    "oldest_finding_age_days": 1
  },
  "risk_burndown": {
    "current_risk_score": 385.5,
    "trend_direction": "worsening",
    "data_points": [
      {
        "date": "2026-02-20",
        "value": 282.66
      },
      {
        "date": "2026-02-21",
        "value": 287.97
      },
      {
        "date": "2026-02-22",
        "value": 295.76
      },
      {
        "date": "2026-02-23",
        "value": 258.13
      },
      {
        "date": "2026-02-24",
        "value": 277.79
      },
      {
        "date": "2026-02-25",
        "value": 267.24
      },
      {
        "date": "2026-02-26",
        "value": 281.63
      },
      {
        "date": "2026-02-27",
        "value": 304.71
      },
      {
        "date": "2026-02-28",
        "value": 324.62
      },
      {
        "date": "2026-03-01",
        "value": 308.29
      },
      {
        "date": "2026-03-02",
        "value": 295.7
      },
      {
        "date": "2026-03-03",
        "value": 304.55
      },
      {
        "date": "2026-03-04",
        "value": 290.4
      },
      {
        "date": "2026-03-05",
        "value": 301.61
      },
      {
        "date": "2026-03-06",
        "value": 350.32
      },
      {
        "date": "2026-03-07",
        "value": 343.65
      },
      {
        "date": "2026-03-08",
        "value": 355.12
      },
      {
        "date": "2026-03-09",
        "value": 341.07
      },
      {
        "date": "2026-03-10",
        "value": 316.74
      },
      {
        "date": "2026-03-11",
        "value": 313.14
      },
      {
        "date": "2026-03-12",
        "value": 363.48
      },
      {
        "date": "2026-03-13",
        "value": 323.53
      },
      {
        "date": "2026-03-14",
        "value": 325.64
      },
      {
        "date": "2026-03-15",
        "value": 362.97
      },
      {
        "date": "2026-03-16",
        "value": 387.09
      },
      {
        "date": "2026-03-17",
        "value": 365.32
      },
      {
        "date": "2026-03-18",
        "value": 346.71
      },
      {
        "date": "2026-03-19",
        "value": 371.64
      },
      {
        "date": "2026-03-20",
        "value": 383.93
      },
      {
        "date": "2026-03-21",
        "value": 385.5
      }
    ],
    "recent_opened": 99,
    "recent_resolved": 0
  },
  "team_velocity": {
    "top_resolvers": [],
    "weekly_resolution": [
      {
        "week_start": "2026-02-21",
        "week_end": "2026-02-28",
        "resolved_count": 0
      },
      {
        "week_start": "2026-02-28",
        "week_end": "2026-03-07",
        "resolved_count": 0
      },
      {
        "week_start": "2026-03-07",
        "week_end": "2026-03-14",
        "resolved_count": 0
      },
      {
        "week_start": "2026-03-14",
        "week_end": "2026-03-21",
        "resolved_count": 0
      }
    ],
    "total_resolved_last_4_weeks": 0,
    "total_resolved_all_time": 0,
    "resolution_rate_pct": 0
  },
  "scanner_effectiveness": {
    "scanners": [
      {
        "scanner": "Semgrep",
        "total_findings": 56,
        "unique_findings": 36,
        "duplicate_findings": 20,
        "duplicate_rate_pct": 35.7,
        "false_positive_count": 0,
        "false_positive_rate_pct": 0,
        "critical_unique_findings": 0,
        "severity_distribution": {
          "high": 38,
          "medium": 18
        }
      },
      {
        "scanner": "Trivy",
        "total_findings": 52,
        "unique_findings": 26,
        "duplicate_findings": 26,
        "duplicate_rate_pct": 50,
        "false_positive_count": 0,
        "false_positive_rate_pct": 0,
        "critical_unique_findings": 5,
        "severity_distribution": {
          "low": 5,
          "high": 23,
          "critical": 9,
          "medium": 15
        }
      },
      {
        "scanner": "Checkov",
        "total_findings": 22,
        "unique_findings": 14,
        "duplicate_findings": 8,
        "duplicate_rate_pct": 36.4,
        "false_positive_count": 0,
        "false_positive_rate_pct": 0,
        "critical_unique_findings": 2,
        "severity_distribution": {
          "low": 4,
          "high": 8,
          "critical": 3,
          "medium": 7
        }
      },
      {
        "scanner": "ZAP",
        "total_findings": 17,
        "unique_findings": 11,
        "duplicate_findings": 6,
        "duplicate_rate_pct": 35.3,
        "false_positive_count": 0,
        "false_positive_rate_pct": 0,
        "critical_unique_findings": 0,
        "severity_distribution": {
          "low": 7,
          "high": 5,
          "info": 1,
          "medium": 4
        }
      },
      {
        "scanner": "Gitleaks",
        "total_findings": 13,
        "unique_findings": 8,
        "duplicate_findings": 5,
        "duplicate_rate_pct": 38.5,
        "false_positive_count": 0,
        "false_positive_rate_pct": 0,
        "critical_unique_findings": 0,
        "severity_distribution": {
          "high": 13
        }
      },
      {
        "scanner": "Bandit",
        "total_findings": 4,
        "unique_findings": 4,
        "duplicate_findings": 0,
        "duplicate_rate_pct": 0,
        "false_positive_count": 0,
        "false_positive_rate_pct": 0,
        "critical_unique_findings": 0,
        "severity_distribution": {
          "low": 1,
          "high": 1,
          "medium": 2
        }
      }
    ],
    "total_scanners": 6
  },
  "vulnerability_trends": {
    "days": 30,
    "data_points": [
      {
        "date": "2026-02-19",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-02-20",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-02-21",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-02-22",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-02-23",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-02-24",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-02-25",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-02-26",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-02-27",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-02-28",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-01",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-02",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-03",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-04",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-05",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-06",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-07",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-08",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-09",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-10",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-11",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-12",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-13",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-14",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-15",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-16",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-17",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-18",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-19",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 0
      },
      {
        "date": "2026-03-20",
        "new_total": 99,
        "resolved_total": 0,
        "new_by_severity": {
          "critical": 7,
          "high": 50,
          "medium": 30,
          "low": 11,
          "info": 1
        },
        "resolved_by_severity": {},
        "net_open": 99
      },
      {
        "date": "2026-03-21",
        "new_total": 0,
        "resolved_total": 0,
        "new_by_severity": {},
        "resolved_by_severity": {},
        "net_open": 99
      }
    ],
    "summary": {
      "total_new": 99,
      "total_resolved": 0,
      "net_change": 99,
      "current_open": 99
    }
  }
}

export const metricsMttr = {
  "overall_mttr_hours": null,
  "by_severity": {
    "critical": null,
    "high": null,
    "medium": null,
    "low": null
  },
  "resolved_count": 0,
  "trend_30d": [
    {
      "date": "2026-02-20",
      "value": 58.41
    },
    {
      "date": "2026-02-21",
      "value": 59.46
    },
    {
      "date": "2026-02-22",
      "value": 62.71
    },
    {
      "date": "2026-02-23",
      "value": 61.35
    },
    {
      "date": "2026-02-24",
      "value": 57.11
    },
    {
      "date": "2026-02-25",
      "value": 57.24
    },
    {
      "date": "2026-02-26",
      "value": 63.15
    },
    {
      "date": "2026-02-27",
      "value": 59.71
    },
    {
      "date": "2026-02-28",
      "value": 54.53
    },
    {
      "date": "2026-03-01",
      "value": 53.41
    },
    {
      "date": "2026-03-02",
      "value": 60.06
    },
    {
      "date": "2026-03-03",
      "value": 58.31
    },
    {
      "date": "2026-03-04",
      "value": 57.9
    },
    {
      "date": "2026-03-05",
      "value": 50.69
    },
    {
      "date": "2026-03-06",
      "value": 50.52
    },
    {
      "date": "2026-03-07",
      "value": 56.24
    },
    {
      "date": "2026-03-08",
      "value": 52.97
    },
    {
      "date": "2026-03-09",
      "value": 51.74
    },
    {
      "date": "2026-03-10",
      "value": 48.84
    },
    {
      "date": "2026-03-11",
      "value": 54.6
    },
    {
      "date": "2026-03-12",
      "value": 52.81
    },
    {
      "date": "2026-03-13",
      "value": 55.53
    },
    {
      "date": "2026-03-14",
      "value": 51.73
    },
    {
      "date": "2026-03-15",
      "value": 50.07
    },
    {
      "date": "2026-03-16",
      "value": 52.41
    },
    {
      "date": "2026-03-17",
      "value": 45.09
    },
    {
      "date": "2026-03-18",
      "value": 44.83
    },
    {
      "date": "2026-03-19",
      "value": 52.84
    },
    {
      "date": "2026-03-20",
      "value": 44.46
    },
    {
      "date": "2026-03-21",
      "value": 48
    }
  ]
}

export const metricsAging = {
  "buckets": {
    "0-7d": {
      "critical": 7,
      "high": 50,
      "medium": 30,
      "low": 11
    },
    "7-30d": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0
    },
    "30-90d": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0
    },
    "90-180d": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0
    },
    "180d+": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0
    }
  },
  "total_by_bucket": {
    "0-7d": 98,
    "7-30d": 0,
    "30-90d": 0,
    "90-180d": 0,
    "180d+": 0
  },
  "total_open": 99,
  "oldest_finding_age_days": 1
}

export const metricsBurndown = {
  "current_risk_score": 385.5,
  "trend_direction": "worsening",
  "data_points": [
    {
      "date": "2026-02-20",
      "value": 282.66
    },
    {
      "date": "2026-02-21",
      "value": 287.97
    },
    {
      "date": "2026-02-22",
      "value": 295.76
    },
    {
      "date": "2026-02-23",
      "value": 258.13
    },
    {
      "date": "2026-02-24",
      "value": 277.79
    },
    {
      "date": "2026-02-25",
      "value": 267.24
    },
    {
      "date": "2026-02-26",
      "value": 281.63
    },
    {
      "date": "2026-02-27",
      "value": 304.71
    },
    {
      "date": "2026-02-28",
      "value": 324.62
    },
    {
      "date": "2026-03-01",
      "value": 308.29
    },
    {
      "date": "2026-03-02",
      "value": 295.7
    },
    {
      "date": "2026-03-03",
      "value": 304.55
    },
    {
      "date": "2026-03-04",
      "value": 290.4
    },
    {
      "date": "2026-03-05",
      "value": 301.61
    },
    {
      "date": "2026-03-06",
      "value": 350.32
    },
    {
      "date": "2026-03-07",
      "value": 343.65
    },
    {
      "date": "2026-03-08",
      "value": 355.12
    },
    {
      "date": "2026-03-09",
      "value": 341.07
    },
    {
      "date": "2026-03-10",
      "value": 316.74
    },
    {
      "date": "2026-03-11",
      "value": 313.14
    },
    {
      "date": "2026-03-12",
      "value": 363.48
    },
    {
      "date": "2026-03-13",
      "value": 323.53
    },
    {
      "date": "2026-03-14",
      "value": 325.64
    },
    {
      "date": "2026-03-15",
      "value": 362.97
    },
    {
      "date": "2026-03-16",
      "value": 387.09
    },
    {
      "date": "2026-03-17",
      "value": 365.32
    },
    {
      "date": "2026-03-18",
      "value": 346.71
    },
    {
      "date": "2026-03-19",
      "value": 371.64
    },
    {
      "date": "2026-03-20",
      "value": 383.93
    },
    {
      "date": "2026-03-21",
      "value": 385.5
    }
  ],
  "recent_opened": 99,
  "recent_resolved": 0
}

export const metricsVelocity = {
  "top_resolvers": [],
  "weekly_resolution": [
    {
      "week_start": "2026-02-21",
      "week_end": "2026-02-28",
      "resolved_count": 0
    },
    {
      "week_start": "2026-02-28",
      "week_end": "2026-03-07",
      "resolved_count": 0
    },
    {
      "week_start": "2026-03-07",
      "week_end": "2026-03-14",
      "resolved_count": 0
    },
    {
      "week_start": "2026-03-14",
      "week_end": "2026-03-21",
      "resolved_count": 0
    }
  ],
  "total_resolved_last_4_weeks": 0,
  "total_resolved_all_time": 0,
  "resolution_rate_pct": 0
}

export const metricsScannerEffectiveness = {
  "scanners": [
    {
      "scanner": "Semgrep",
      "total_findings": 56,
      "unique_findings": 36,
      "duplicate_findings": 20,
      "duplicate_rate_pct": 35.7,
      "false_positive_count": 0,
      "false_positive_rate_pct": 0,
      "critical_unique_findings": 0,
      "severity_distribution": {
        "high": 38,
        "medium": 18
      }
    },
    {
      "scanner": "Trivy",
      "total_findings": 52,
      "unique_findings": 26,
      "duplicate_findings": 26,
      "duplicate_rate_pct": 50,
      "false_positive_count": 0,
      "false_positive_rate_pct": 0,
      "critical_unique_findings": 5,
      "severity_distribution": {
        "low": 5,
        "high": 23,
        "critical": 9,
        "medium": 15
      }
    },
    {
      "scanner": "Checkov",
      "total_findings": 22,
      "unique_findings": 14,
      "duplicate_findings": 8,
      "duplicate_rate_pct": 36.4,
      "false_positive_count": 0,
      "false_positive_rate_pct": 0,
      "critical_unique_findings": 2,
      "severity_distribution": {
        "low": 4,
        "high": 8,
        "critical": 3,
        "medium": 7
      }
    },
    {
      "scanner": "ZAP",
      "total_findings": 17,
      "unique_findings": 11,
      "duplicate_findings": 6,
      "duplicate_rate_pct": 35.3,
      "false_positive_count": 0,
      "false_positive_rate_pct": 0,
      "critical_unique_findings": 0,
      "severity_distribution": {
        "low": 7,
        "high": 5,
        "info": 1,
        "medium": 4
      }
    },
    {
      "scanner": "Gitleaks",
      "total_findings": 13,
      "unique_findings": 8,
      "duplicate_findings": 5,
      "duplicate_rate_pct": 38.5,
      "false_positive_count": 0,
      "false_positive_rate_pct": 0,
      "critical_unique_findings": 0,
      "severity_distribution": {
        "high": 13
      }
    },
    {
      "scanner": "Bandit",
      "total_findings": 4,
      "unique_findings": 4,
      "duplicate_findings": 0,
      "duplicate_rate_pct": 0,
      "false_positive_count": 0,
      "false_positive_rate_pct": 0,
      "critical_unique_findings": 0,
      "severity_distribution": {
        "low": 1,
        "high": 1,
        "medium": 2
      }
    }
  ],
  "total_scanners": 6
}

export const metricsTrends = {
  "days": 90,
  "data_points": [
    {
      "date": "2025-12-21",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2025-12-22",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2025-12-23",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2025-12-24",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2025-12-25",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2025-12-26",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2025-12-27",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2025-12-28",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2025-12-29",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2025-12-30",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2025-12-31",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-01",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-02",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-03",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-04",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-05",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-06",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-07",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-08",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-09",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-10",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-11",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-12",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-13",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-14",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-15",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-16",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-17",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-18",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-19",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-20",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-21",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-22",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-23",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-24",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-25",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-26",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-27",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-28",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-29",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-30",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-01-31",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-01",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-02",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-03",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-04",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-05",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-06",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-07",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-08",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-09",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-10",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-11",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-12",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-13",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-14",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-15",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-16",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-17",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-18",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-19",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-20",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-21",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-22",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-23",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-24",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-25",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-26",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-27",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-02-28",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-01",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-02",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-03",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-04",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-05",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-06",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-07",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-08",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-09",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-10",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-11",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-12",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-13",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-14",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-15",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-16",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-17",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-18",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-19",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 0
    },
    {
      "date": "2026-03-20",
      "new_total": 99,
      "resolved_total": 0,
      "new_by_severity": {
        "critical": 7,
        "high": 50,
        "medium": 30,
        "low": 11,
        "info": 1
      },
      "resolved_by_severity": {},
      "net_open": 99
    },
    {
      "date": "2026-03-21",
      "new_total": 0,
      "resolved_total": 0,
      "new_by_severity": {},
      "resolved_by_severity": {},
      "net_open": 99
    }
  ],
  "summary": {
    "total_new": 99,
    "total_resolved": 0,
    "net_change": 99,
    "current_open": 99
  }
}

export const metricsExecutiveSummary = {
  "overall_risk_level": "critical",
  "risk_trend": "stable",
  "key_metrics": {
    "total_open": 99,
    "critical_open": 7,
    "high_open": 50,
    "mttr_critical_hours": null,
    "sla_compliance_rate": 100,
    "findings_last_7d": 99,
    "resolved_last_7d": 0
  },
  "highlights": [
    "7 critical finding(s) require immediate attention.",
    "99 new finding(s) discovered in the past 7 days."
  ],
  "action_items": [
    "Remediate 7 critical finding(s) within SLA deadlines.",
    "Address 50 high-severity open findings to reduce risk exposure."
  ]
}

export const attackPathsOverview = {
  "total_attack_paths": 6,
  "critical_paths": 6,
  "products_at_risk": 4,
  "total_products": 5,
  "product_breakdown": [
    {
      "product_id": 5,
      "product_name": "Internal Admin Dashboard",
      "attack_path_count": 2,
      "critical_paths": 2,
      "highest_risk_score": 86,
      "top_path": "Full System Compromise via Insecure Deserialization + RCE"
    },
    {
      "product_id": 4,
      "product_name": "Mobile Banking App",
      "attack_path_count": 1,
      "critical_paths": 1,
      "highest_risk_score": 86,
      "top_path": "Full System Compromise via Insecure Deserialization + RCE"
    },
    {
      "product_id": 1,
      "product_name": "Payment Gateway",
      "attack_path_count": 2,
      "critical_paths": 2,
      "highest_risk_score": 86,
      "top_path": "Full System Compromise via Insecure Deserialization + RCE"
    },
    {
      "product_id": 2,
      "product_name": "Customer Portal",
      "attack_path_count": 1,
      "critical_paths": 1,
      "highest_risk_score": 83,
      "top_path": "Data Breach via SQL Injection + Sensitive Data Exposure"
    }
  ]
}

export const attackPathsProduct = {
  "product_id": 1,
  "product_name": "Payment Gateway",
  "attack_paths": [
    {
      "id": 2,
      "name": "Full System Compromise via Insecure Deserialization + RCE",
      "description": "Insecure deserialization provides a code execution primitive that, combined with other RCE vectors, leads to full system compromise.",
      "risk_score": 86,
      "nodes": [
        {
          "finding_id": 7,
          "title": "python.lang.security.deserialization.avoid-pickle",
          "severity": "high",
          "cwe": 502
        },
        {
          "finding_id": 46,
          "title": "python.lang.security.deserialization.avoid-pickle",
          "severity": "high",
          "cwe": 502
        },
        {
          "finding_id": 1,
          "title": "python.lang.security.audit.dangerous-subprocess-use",
          "severity": "high",
          "cwe": 78
        },
        {
          "finding_id": 43,
          "title": "python.lang.security.audit.dangerous-system-call",
          "severity": "high",
          "cwe": 78
        }
      ],
      "edges": [
        {
          "source": 46,
          "target": 1,
          "relationship": "enables"
        },
        {
          "source": 46,
          "target": 43,
          "relationship": "enables"
        },
        {
          "source": 7,
          "target": 1,
          "relationship": "enables"
        },
        {
          "source": 7,
          "target": 43,
          "relationship": "enables"
        }
      ],
      "likelihood": "medium",
      "impact": "critical",
      "mitigation_priority": "immediate"
    },
    {
      "id": 1,
      "name": "Data Breach via SQL Injection + Sensitive Data Exposure",
      "description": "SQL injection provides database access while sensitive data exposure ensures extracted data is unprotected, leading to a full data breach.",
      "risk_score": 83,
      "nodes": [
        {
          "finding_id": 3,
          "title": "python.lang.security.audit.sqli.string-concat-query",
          "severity": "high",
          "cwe": 89
        },
        {
          "finding_id": 44,
          "title": "python.lang.security.audit.sqli",
          "severity": "high",
          "cwe": 89
        },
        {
          "finding_id": 8,
          "title": "python.lang.security.audit.insecure-transport",
          "severity": "medium",
          "cwe": 319
        }
      ],
      "edges": [
        {
          "source": 3,
          "target": 8,
          "relationship": "enables"
        },
        {
          "source": 44,
          "target": 8,
          "relationship": "enables"
        }
      ],
      "likelihood": "high",
      "impact": "critical",
      "mitigation_priority": "immediate"
    }
  ],
  "total": 2
}

export const attackPathsSurface = {
  "product_id": 1,
  "total_findings": 23,
  "entry_points": [],
  "internal_weaknesses": [
    {
      "finding_id": 1,
      "title": "python.lang.security.audit.dangerous-subprocess-use",
      "severity": "high",
      "cwe": 78,
      "tool_type": "SAST"
    },
    {
      "finding_id": 2,
      "title": "python.lang.security.audit.eval-detected",
      "severity": "high",
      "cwe": 95,
      "tool_type": "SAST"
    },
    {
      "finding_id": 3,
      "title": "python.lang.security.audit.sqli.string-concat-query",
      "severity": "high",
      "cwe": 89,
      "tool_type": "SAST"
    },
    {
      "finding_id": 5,
      "title": "python.lang.security.audit.hardcoded-password",
      "severity": "high",
      "cwe": 798,
      "tool_type": "SAST"
    },
    {
      "finding_id": 7,
      "title": "python.lang.security.deserialization.avoid-pickle",
      "severity": "high",
      "cwe": 502,
      "tool_type": "SAST"
    },
    {
      "finding_id": 43,
      "title": "python.lang.security.audit.dangerous-system-call",
      "severity": "high",
      "cwe": 78,
      "tool_type": "SAST"
    },
    {
      "finding_id": 44,
      "title": "python.lang.security.audit.sqli",
      "severity": "high",
      "cwe": 89,
      "tool_type": "SAST"
    },
    {
      "finding_id": 46,
      "title": "python.lang.security.deserialization.avoid-pickle",
      "severity": "high",
      "cwe": 502,
      "tool_type": "SAST"
    },
    {
      "finding_id": 47,
      "title": "python.lang.security.audit.insecure-hash",
      "severity": "high",
      "cwe": 327,
      "tool_type": "SAST"
    },
    {
      "finding_id": 48,
      "title": "python.lang.security.audit.ssrf-requests",
      "severity": "high",
      "cwe": 918,
      "tool_type": "SAST"
    },
    {
      "finding_id": 50,
      "title": "python.lang.security.audit.path-traversal",
      "severity": "high",
      "cwe": 22,
      "tool_type": "SAST"
    },
    {
      "finding_id": 52,
      "title": "python.lang.security.audit.insecure-jwt",
      "severity": "high",
      "cwe": 287,
      "tool_type": "SAST"
    },
    {
      "finding_id": 72,
      "title": "Secret Detected: aws-access-key-id",
      "severity": "high",
      "cwe": null,
      "tool_type": "Secret Detection"
    },
    {
      "finding_id": 73,
      "title": "Secret Detected: generic-api-key",
      "severity": "high",
      "cwe": null,
      "tool_type": "Secret Detection"
    },
    {
      "finding_id": 74,
      "title": "Secret Detected: private-key",
      "severity": "high",
      "cwe": null,
      "tool_type": "Secret Detection"
    },
    {
      "finding_id": 75,
      "title": "Secret Detected: github-pat",
      "severity": "high",
      "cwe": null,
      "tool_type": "Secret Detection"
    },
    {
      "finding_id": 76,
      "title": "Secret Detected: generic-password",
      "severity": "high",
      "cwe": null,
      "tool_type": "Secret Detection"
    },
    {
      "finding_id": 4,
      "title": "python.lang.security.audit.insecure-hash-algorithm",
      "severity": "medium",
      "cwe": 327,
      "tool_type": "SAST"
    },
    {
      "finding_id": 6,
      "title": "python.flask.security.xss.direct-use-of-jinja2",
      "severity": "medium",
      "cwe": 79,
      "tool_type": "SAST"
    },
    {
      "finding_id": 8,
      "title": "python.lang.security.audit.insecure-transport",
      "severity": "medium",
      "cwe": 319,
      "tool_type": "SAST"
    },
    {
      "finding_id": 45,
      "title": "python.lang.security.audit.xss-template",
      "severity": "medium",
      "cwe": 79,
      "tool_type": "SAST"
    },
    {
      "finding_id": 49,
      "title": "python.lang.security.audit.open-redirect",
      "severity": "medium",
      "cwe": 601,
      "tool_type": "SAST"
    },
    {
      "finding_id": 51,
      "title": "python.lang.security.audit.csrf-disabled",
      "severity": "medium",
      "cwe": 352,
      "tool_type": "SAST"
    }
  ],
  "data_stores": [
    {
      "finding_id": 3,
      "title": "python.lang.security.audit.sqli.string-concat-query",
      "severity": "high",
      "cwe": 89,
      "tool_type": "SAST"
    },
    {
      "finding_id": 44,
      "title": "python.lang.security.audit.sqli",
      "severity": "high",
      "cwe": 89,
      "tool_type": "SAST"
    },
    {
      "finding_id": 47,
      "title": "python.lang.security.audit.insecure-hash",
      "severity": "high",
      "cwe": 327,
      "tool_type": "SAST"
    },
    {
      "finding_id": 4,
      "title": "python.lang.security.audit.insecure-hash-algorithm",
      "severity": "medium",
      "cwe": 327,
      "tool_type": "SAST"
    }
  ],
  "external_services": [
    {
      "finding_id": 48,
      "title": "python.lang.security.audit.ssrf-requests",
      "severity": "high",
      "cwe": 918,
      "tool_type": "SAST"
    },
    {
      "finding_id": 51,
      "title": "python.lang.security.audit.csrf-disabled",
      "severity": "medium",
      "cwe": 352,
      "tool_type": "SAST"
    }
  ],
  "discovered_endpoints": [],
  "summary": {
    "entry_point_count": 0,
    "internal_weakness_count": 23,
    "data_store_count": 4,
    "external_service_count": 2,
    "endpoint_count": 0
  },
  "product_name": "Payment Gateway"
}

export const attackPathsGraph = {
  "product_id": 1,
  "nodes": [
    {
      "id": 7,
      "label": "python.lang.security.deserialization.avoid-pickle",
      "severity": "high",
      "cwe": 502,
      "attack_paths": [
        "Full System Compromise via Insecure Deserialization + RCE"
      ]
    },
    {
      "id": 46,
      "label": "python.lang.security.deserialization.avoid-pickle",
      "severity": "high",
      "cwe": 502,
      "attack_paths": [
        "Full System Compromise via Insecure Deserialization + RCE"
      ]
    },
    {
      "id": 1,
      "label": "python.lang.security.audit.dangerous-subprocess-use",
      "severity": "high",
      "cwe": 78,
      "attack_paths": [
        "Full System Compromise via Insecure Deserialization + RCE"
      ]
    },
    {
      "id": 43,
      "label": "python.lang.security.audit.dangerous-system-call",
      "severity": "high",
      "cwe": 78,
      "attack_paths": [
        "Full System Compromise via Insecure Deserialization + RCE"
      ]
    },
    {
      "id": 3,
      "label": "python.lang.security.audit.sqli.string-concat-query",
      "severity": "high",
      "cwe": 89,
      "attack_paths": [
        "Data Breach via SQL Injection + Sensitive Data Exposure"
      ]
    },
    {
      "id": 44,
      "label": "python.lang.security.audit.sqli",
      "severity": "high",
      "cwe": 89,
      "attack_paths": [
        "Data Breach via SQL Injection + Sensitive Data Exposure"
      ]
    },
    {
      "id": 8,
      "label": "python.lang.security.audit.insecure-transport",
      "severity": "medium",
      "cwe": 319,
      "attack_paths": [
        "Data Breach via SQL Injection + Sensitive Data Exposure"
      ]
    }
  ],
  "edges": [
    {
      "source": 46,
      "target": 1,
      "relationship": "enables",
      "attack_path": "Full System Compromise via Insecure Deserialization + RCE"
    },
    {
      "source": 46,
      "target": 43,
      "relationship": "enables",
      "attack_path": "Full System Compromise via Insecure Deserialization + RCE"
    },
    {
      "source": 7,
      "target": 1,
      "relationship": "enables",
      "attack_path": "Full System Compromise via Insecure Deserialization + RCE"
    },
    {
      "source": 7,
      "target": 43,
      "relationship": "enables",
      "attack_path": "Full System Compromise via Insecure Deserialization + RCE"
    },
    {
      "source": 3,
      "target": 8,
      "relationship": "enables",
      "attack_path": "Data Breach via SQL Injection + Sensitive Data Exposure"
    },
    {
      "source": 44,
      "target": 8,
      "relationship": "enables",
      "attack_path": "Data Breach via SQL Injection + Sensitive Data Exposure"
    }
  ],
  "total_paths": 2,
  "highest_risk": 86,
  "product_name": "Payment Gateway"
}

export const sbomOverview = {
  "total_products": 5,
  "products_with_sbom": 0,
  "total_components": 96,
  "total_vulnerabilities": 68,
  "total_license_risks": 8,
  "total_supply_chain_issues": 31,
  "ecosystem_distribution": {
    "javascript": 28,
    "python": 64,
    "generic": 4
  },
  "component_type_distribution": {
    "library": 70,
    "framework": 26
  },
  "products": [
    {
      "product_id": 2,
      "product_name": "Customer Portal",
      "has_uploaded_sbom": false,
      "component_count": 19,
      "vulnerability_count": 14,
      "license_risk_count": 1,
      "supply_chain_risk_level": "high",
      "overall_risk": "critical"
    },
    {
      "product_id": 3,
      "product_name": "Infrastructure Platform",
      "has_uploaded_sbom": false,
      "component_count": 24,
      "vulnerability_count": 16,
      "license_risk_count": 2,
      "supply_chain_risk_level": "high",
      "overall_risk": "critical"
    },
    {
      "product_id": 5,
      "product_name": "Internal Admin Dashboard",
      "has_uploaded_sbom": false,
      "component_count": 21,
      "vulnerability_count": 13,
      "license_risk_count": 2,
      "supply_chain_risk_level": "high",
      "overall_risk": "critical"
    },
    {
      "product_id": 4,
      "product_name": "Mobile Banking App",
      "has_uploaded_sbom": false,
      "component_count": 16,
      "vulnerability_count": 13,
      "license_risk_count": 1,
      "supply_chain_risk_level": "high",
      "overall_risk": "critical"
    },
    {
      "product_id": 1,
      "product_name": "Payment Gateway",
      "has_uploaded_sbom": false,
      "component_count": 16,
      "vulnerability_count": 12,
      "license_risk_count": 2,
      "supply_chain_risk_level": "high",
      "overall_risk": "critical"
    }
  ]
}

export const sbomProduct = {
  "product_id": 1,
  "product_name": "Payment Gateway",
  "generated_at": "2026-03-21T12:12:15.997945+00:00",
  "total_components": 16,
  "by_type": {
    "framework": 6,
    "library": 10
  },
  "by_language": {
    "javascript": 5,
    "python": 10,
    "generic": 1
  },
  "license_distribution": {
    "MIT": 7,
    "BSD-3-Clause": 5,
    "AGPL-3.0": 1,
    "Apache-2.0": 2,
    "GPL-3.0": 1
  },
  "vulnerability_correlation": {
    "matched_findings_count": 0,
    "matched_findings": [],
    "known_vuln_matches": 12,
    "known_vulnerabilities": [
      {
        "package": "express",
        "version": "4.18.2",
        "cve": "CVE-2024-29041",
        "severity": "medium",
        "summary": "Open redirect via URL parsing",
        "fixed_in": "4.19.2",
        "is_affected": true
      },
      {
        "package": "flask",
        "version": "2.3.0",
        "cve": "CVE-2023-30861",
        "severity": "high",
        "summary": "Cookie caching on shared proxies allows session hijacking",
        "fixed_in": "2.3.2",
        "is_affected": true
      },
      {
        "package": "django",
        "version": "4.2.7",
        "cve": "CVE-2024-27351",
        "severity": "high",
        "summary": "ReDoS in django.utils.text.Truncator",
        "fixed_in": "4.2.11",
        "is_affected": true
      },
      {
        "package": "jsonwebtoken",
        "version": "8.5.1",
        "cve": "CVE-2022-23529",
        "severity": "critical",
        "summary": "Insecure key retrieval allows JWT forgery",
        "fixed_in": "9.0.0",
        "is_affected": true
      },
      {
        "package": "scikit-learn",
        "version": "0.23.2",
        "cve": "CVE-2020-28975",
        "severity": "medium",
        "summary": "Denial of service via malicious pickle model",
        "fixed_in": "0.24.0",
        "is_affected": true
      },
      {
        "package": "axios",
        "version": "1.4.0",
        "cve": "CVE-2023-45857",
        "severity": "high",
        "summary": "CSRF token exposure via XSRF-TOKEN cookie",
        "fixed_in": "1.6.0",
        "is_affected": true
      },
      {
        "package": "pytorch",
        "version": "1.13.0",
        "cve": "CVE-2024-31583",
        "severity": "high",
        "summary": "Arbitrary code execution via torch.load with pickle",
        "fixed_in": "2.2.0",
        "is_affected": true
      },
      {
        "package": "lodash",
        "version": "4.17.20",
        "cve": "CVE-2021-23337",
        "severity": "high",
        "summary": "Command injection via template function",
        "fixed_in": "4.17.21",
        "is_affected": true
      },
      {
        "package": "lodash",
        "version": "4.17.20",
        "cve": "CVE-2020-28500",
        "severity": "medium",
        "summary": "ReDoS in toNumber, trim, trimEnd",
        "fixed_in": "4.17.21",
        "is_affected": true
      },
      {
        "package": "onnx",
        "version": "1.14.0",
        "cve": "CVE-2024-27318",
        "severity": "high",
        "summary": "Directory traversal in ONNX model extraction",
        "fixed_in": "1.16.0",
        "is_affected": true
      },
      {
        "package": "tensorflow",
        "version": "2.11.0",
        "cve": "CVE-2023-25801",
        "severity": "critical",
        "summary": "OOB read in TFLite GPU delegate",
        "fixed_in": "2.12.0",
        "is_affected": true
      },
      {
        "package": "tensorflow",
        "version": "2.11.0",
        "cve": "CVE-2023-25660",
        "severity": "high",
        "summary": "Heap buffer overflow in AvgPool3DGrad",
        "fixed_in": "2.12.0",
        "is_affected": true
      }
    ],
    "unmatched_components": 16
  },
  "dependency_analysis": {
    "known_vulnerabilities": [
      {
        "package": "express",
        "version": "4.18.2",
        "cve": "CVE-2024-29041",
        "severity": "medium",
        "summary": "Open redirect via URL parsing",
        "fixed_in": "4.19.2",
        "is_affected": true
      },
      {
        "package": "flask",
        "version": "2.3.0",
        "cve": "CVE-2023-30861",
        "severity": "high",
        "summary": "Cookie caching on shared proxies allows session hijacking",
        "fixed_in": "2.3.2",
        "is_affected": true
      },
      {
        "package": "django",
        "version": "4.2.7",
        "cve": "CVE-2024-27351",
        "severity": "high",
        "summary": "ReDoS in django.utils.text.Truncator",
        "fixed_in": "4.2.11",
        "is_affected": true
      },
      {
        "package": "jsonwebtoken",
        "version": "8.5.1",
        "cve": "CVE-2022-23529",
        "severity": "critical",
        "summary": "Insecure key retrieval allows JWT forgery",
        "fixed_in": "9.0.0",
        "is_affected": true
      },
      {
        "package": "scikit-learn",
        "version": "0.23.2",
        "cve": "CVE-2020-28975",
        "severity": "medium",
        "summary": "Denial of service via malicious pickle model",
        "fixed_in": "0.24.0",
        "is_affected": true
      },
      {
        "package": "axios",
        "version": "1.4.0",
        "cve": "CVE-2023-45857",
        "severity": "high",
        "summary": "CSRF token exposure via XSRF-TOKEN cookie",
        "fixed_in": "1.6.0",
        "is_affected": true
      },
      {
        "package": "pytorch",
        "version": "1.13.0",
        "cve": "CVE-2024-31583",
        "severity": "high",
        "summary": "Arbitrary code execution via torch.load with pickle",
        "fixed_in": "2.2.0",
        "is_affected": true
      },
      {
        "package": "lodash",
        "version": "4.17.20",
        "cve": "CVE-2021-23337",
        "severity": "high",
        "summary": "Command injection via template function",
        "fixed_in": "4.17.21",
        "is_affected": true
      },
      {
        "package": "lodash",
        "version": "4.17.20",
        "cve": "CVE-2020-28500",
        "severity": "medium",
        "summary": "ReDoS in toNumber, trim, trimEnd",
        "fixed_in": "4.17.21",
        "is_affected": true
      },
      {
        "package": "onnx",
        "version": "1.14.0",
        "cve": "CVE-2024-27318",
        "severity": "high",
        "summary": "Directory traversal in ONNX model extraction",
        "fixed_in": "1.16.0",
        "is_affected": true
      },
      {
        "package": "tensorflow",
        "version": "2.11.0",
        "cve": "CVE-2023-25801",
        "severity": "critical",
        "summary": "OOB read in TFLite GPU delegate",
        "fixed_in": "2.12.0",
        "is_affected": true
      },
      {
        "package": "tensorflow",
        "version": "2.11.0",
        "cve": "CVE-2023-25660",
        "severity": "high",
        "summary": "Heap buffer overflow in AvgPool3DGrad",
        "fixed_in": "2.12.0",
        "is_affected": true
      }
    ],
    "outdated_packages": [
      {
        "package": "express",
        "current_version": "4.18.2",
        "recommended_version": "4.19.2",
        "severity": "medium",
        "detail": "Version 4.18.2 is older than the recommended 4.19.2."
      },
      {
        "package": "flask",
        "current_version": "2.3.0",
        "recommended_version": "2.3.2",
        "severity": "medium",
        "detail": "Version 2.3.0 is older than the recommended 2.3.2."
      },
      {
        "package": "django",
        "current_version": "4.2.7",
        "recommended_version": "4.2.11",
        "severity": "medium",
        "detail": "Version 4.2.7 is older than the recommended 4.2.11."
      },
      {
        "package": "jsonwebtoken",
        "current_version": "8.5.1",
        "recommended_version": "9.0.0",
        "severity": "medium",
        "detail": "Version 8.5.1 is older than the recommended 9.0.0."
      },
      {
        "package": "scikit-learn",
        "current_version": "0.23.2",
        "recommended_version": "0.24.0",
        "severity": "medium",
        "detail": "Version 0.23.2 is older than the recommended 0.24.0."
      },
      {
        "package": "axios",
        "current_version": "1.4.0",
        "recommended_version": "1.6.0",
        "severity": "medium",
        "detail": "Version 1.4.0 is older than the recommended 1.6.0."
      },
      {
        "package": "pytorch",
        "current_version": "1.13.0",
        "recommended_version": "2.2.0",
        "severity": "medium",
        "detail": "Version 1.13.0 is older than the recommended 2.2.0."
      },
      {
        "package": "lodash",
        "current_version": "4.17.20",
        "recommended_version": "4.17.21",
        "severity": "medium",
        "detail": "Version 4.17.20 is older than the recommended 4.17.21."
      },
      {
        "package": "onnx",
        "current_version": "1.14.0",
        "recommended_version": "1.16.0",
        "severity": "medium",
        "detail": "Version 1.14.0 is older than the recommended 1.16.0."
      },
      {
        "package": "tensorflow",
        "current_version": "2.11.0",
        "recommended_version": "2.12.0",
        "severity": "medium",
        "detail": "Version 2.11.0 is older than the recommended 2.12.0."
      }
    ],
    "license_risks": [
      {
        "package": "mongo-connector",
        "version": "3.1.1",
        "license": "AGPL-3.0",
        "risk_type": "copyleft",
        "severity": "high",
        "detail": "License 'AGPL-3.0' may impose copyleft obligations on proprietary / commercial software."
      },
      {
        "package": "readline",
        "version": "8.2.0",
        "license": "GPL-3.0",
        "risk_type": "copyleft",
        "severity": "medium",
        "detail": "License 'GPL-3.0' may impose copyleft obligations on proprietary / commercial software."
      }
    ],
    "typosquatting_candidates": [],
    "duplicate_dependencies": [],
    "transitive_risk_score": 100,
    "total_components": 16
  },
  "supply_chain_risks": {
    "overall_risk_level": "high",
    "malicious_packages": [],
    "typosquatting_candidates": [
      {
        "package": "pytorch",
        "similar_to": "torch",
        "similarity": 0.833,
        "severity": "high",
        "detail": "'pytorch' is suspiciously similar to popular package 'torch'."
      }
    ],
    "suspicious_install_scripts": [],
    "low_reputation_packages": [],
    "ml_model_risks": [
      {
        "package": "pytorch",
        "version": "1.13.0",
        "severity": "high",
        "category": "ml_supply_chain",
        "risks": [
          "No model card or provenance documentation found",
          "No integrity hashes provided — cannot verify model has not been tampered with",
          "PyTorch < 2.0 defaults to unsafe pickle deserialization in torch.load()"
        ],
        "recommendation": "Use SafeTensors format where possible. Pin model revisions by hash. Verify model checksums before loading. Avoid pickle deserialization of untrusted models."
      },
      {
        "package": "onnx",
        "version": "1.14.0",
        "severity": "high",
        "category": "ml_supply_chain",
        "risks": [
          "No model card or provenance documentation found",
          "No integrity hashes provided — cannot verify model has not been tampered with"
        ],
        "recommendation": "Use SafeTensors format where possible. Pin model revisions by hash. Verify model checksums before loading. Avoid pickle deserialization of untrusted models."
      },
      {
        "package": "tensorflow",
        "version": "2.11.0",
        "severity": "high",
        "category": "ml_supply_chain",
        "risks": [
          "No model card or provenance documentation found",
          "No integrity hashes provided — cannot verify model has not been tampered with"
        ],
        "recommendation": "Use SafeTensors format where possible. Pin model revisions by hash. Verify model checksums before loading. Avoid pickle deserialization of untrusted models."
      }
    ],
    "total_issues": 4
  },
  "risk_summary": {
    "overall_risk": "critical",
    "critical_vulnerabilities": 2,
    "high_vulnerabilities": 7,
    "total_license_risks": 2,
    "total_supply_chain_issues": 4,
    "transitive_risk_score": 100,
    "recommendations": [
      "Immediately patch 2 critical vulnerability/ies.",
      "Remediate 7 high-severity vulnerability/ies within 7 days.",
      "Review copyleft-licensed dependencies for commercial compatibility.",
      "Audit ML model provenance and switch to SafeTensors format where possible.",
      "Update outdated packages to their recommended versions."
    ]
  },
  "components": [
    {
      "name": "express",
      "version": "4.18.2",
      "type": "framework",
      "purl": "pkg:npm/express@4.18.2",
      "licenses": [
        "MIT"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-express",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "javascript"
    },
    {
      "name": "flask",
      "version": "2.3.0",
      "type": "framework",
      "purl": "pkg:pypi/flask@2.3.0",
      "licenses": [
        "BSD-3-Clause"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-flask",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "django",
      "version": "4.2.7",
      "type": "framework",
      "purl": "pkg:pypi/django@4.2.7",
      "licenses": [
        "BSD-3-Clause"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-django",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "redis",
      "version": "5.0.1",
      "type": "library",
      "purl": "pkg:pypi/redis@5.0.1",
      "licenses": [
        "MIT"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-redis",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "react",
      "version": "18.2.0",
      "type": "framework",
      "purl": "pkg:npm/react@18.2.0",
      "licenses": [
        "MIT"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-react",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "javascript"
    },
    {
      "name": "jsonwebtoken",
      "version": "8.5.1",
      "type": "library",
      "purl": "pkg:npm/jsonwebtoken@8.5.1",
      "licenses": [
        "MIT"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-jsonwebtoken",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "javascript"
    },
    {
      "name": "scikit-learn",
      "version": "0.23.2",
      "type": "library",
      "purl": "pkg:pypi/scikit-learn@0.23.2",
      "licenses": [
        "BSD-3-Clause"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-scikit-learn",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "axios",
      "version": "1.4.0",
      "type": "library",
      "purl": "pkg:npm/axios@1.4.0",
      "licenses": [
        "MIT"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-axios",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "javascript"
    },
    {
      "name": "sqlalchemy",
      "version": "2.0.23",
      "type": "library",
      "purl": "pkg:pypi/sqlalchemy@2.0.23",
      "licenses": [
        "MIT"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-sqlalchemy",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "mongo-connector",
      "version": "3.1.1",
      "type": "library",
      "purl": "pkg:pypi/mongo-connector@3.1.1",
      "licenses": [
        "AGPL-3.0"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-mongo-connector",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "pytorch",
      "version": "1.13.0",
      "type": "framework",
      "purl": "pkg:pypi/pytorch@1.13.0",
      "licenses": [
        "BSD-3-Clause"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-pytorch",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "lodash",
      "version": "4.17.20",
      "type": "library",
      "purl": "pkg:npm/lodash@4.17.20",
      "licenses": [
        "MIT"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-lodash",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "javascript"
    },
    {
      "name": "onnx",
      "version": "1.14.0",
      "type": "library",
      "purl": "pkg:pypi/onnx@1.14.0",
      "licenses": [
        "Apache-2.0"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-onnx",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "pandas",
      "version": "2.1.4",
      "type": "library",
      "purl": "pkg:pypi/pandas@2.1.4",
      "licenses": [
        "BSD-3-Clause"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-pandas",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "readline",
      "version": "8.2.0",
      "type": "library",
      "purl": "pkg:generic/readline@8.2.0",
      "licenses": [
        "GPL-3.0"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-readline",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "generic"
    },
    {
      "name": "tensorflow",
      "version": "2.11.0",
      "type": "framework",
      "purl": "pkg:pypi/tensorflow@2.11.0",
      "licenses": [
        "Apache-2.0"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-tensorflow",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    }
  ]
}

export const sbomComponents = {
  "product_id": 1,
  "product_name": "Payment Gateway",
  "total_components": 16,
  "by_type": {
    "framework": 6,
    "library": 10
  },
  "by_ecosystem": {
    "javascript": 5,
    "python": 10,
    "generic": 1
  },
  "components": [
    {
      "name": "express",
      "version": "4.18.2",
      "type": "framework",
      "purl": "pkg:npm/express@4.18.2",
      "licenses": [
        "MIT"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-express",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "javascript"
    },
    {
      "name": "flask",
      "version": "2.3.0",
      "type": "framework",
      "purl": "pkg:pypi/flask@2.3.0",
      "licenses": [
        "BSD-3-Clause"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-flask",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "django",
      "version": "4.2.7",
      "type": "framework",
      "purl": "pkg:pypi/django@4.2.7",
      "licenses": [
        "BSD-3-Clause"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-django",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "redis",
      "version": "5.0.1",
      "type": "library",
      "purl": "pkg:pypi/redis@5.0.1",
      "licenses": [
        "MIT"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-redis",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "react",
      "version": "18.2.0",
      "type": "framework",
      "purl": "pkg:npm/react@18.2.0",
      "licenses": [
        "MIT"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-react",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "javascript"
    },
    {
      "name": "jsonwebtoken",
      "version": "8.5.1",
      "type": "library",
      "purl": "pkg:npm/jsonwebtoken@8.5.1",
      "licenses": [
        "MIT"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-jsonwebtoken",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "javascript"
    },
    {
      "name": "scikit-learn",
      "version": "0.23.2",
      "type": "library",
      "purl": "pkg:pypi/scikit-learn@0.23.2",
      "licenses": [
        "BSD-3-Clause"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-scikit-learn",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "axios",
      "version": "1.4.0",
      "type": "library",
      "purl": "pkg:npm/axios@1.4.0",
      "licenses": [
        "MIT"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-axios",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "javascript"
    },
    {
      "name": "sqlalchemy",
      "version": "2.0.23",
      "type": "library",
      "purl": "pkg:pypi/sqlalchemy@2.0.23",
      "licenses": [
        "MIT"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-sqlalchemy",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "mongo-connector",
      "version": "3.1.1",
      "type": "library",
      "purl": "pkg:pypi/mongo-connector@3.1.1",
      "licenses": [
        "AGPL-3.0"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-mongo-connector",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "pytorch",
      "version": "1.13.0",
      "type": "framework",
      "purl": "pkg:pypi/pytorch@1.13.0",
      "licenses": [
        "BSD-3-Clause"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-pytorch",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "lodash",
      "version": "4.17.20",
      "type": "library",
      "purl": "pkg:npm/lodash@4.17.20",
      "licenses": [
        "MIT"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-lodash",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "javascript"
    },
    {
      "name": "onnx",
      "version": "1.14.0",
      "type": "library",
      "purl": "pkg:pypi/onnx@1.14.0",
      "licenses": [
        "Apache-2.0"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-onnx",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "pandas",
      "version": "2.1.4",
      "type": "library",
      "purl": "pkg:pypi/pandas@2.1.4",
      "licenses": [
        "BSD-3-Clause"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-pandas",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    },
    {
      "name": "readline",
      "version": "8.2.0",
      "type": "library",
      "purl": "pkg:generic/readline@8.2.0",
      "licenses": [
        "GPL-3.0"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-readline",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "generic"
    },
    {
      "name": "tensorflow",
      "version": "2.11.0",
      "type": "framework",
      "purl": "pkg:pypi/tensorflow@2.11.0",
      "licenses": [
        "Apache-2.0"
      ],
      "group": "",
      "publisher": "",
      "scope": "required",
      "hashes": {},
      "description": "",
      "bom_ref": "ref-tensorflow",
      "cpe": "",
      "model_card_url": null,
      "ecosystem": "python"
    }
  ]
}

export const sbomVulnerabilities = {
  "product_id": 1,
  "product_name": "Payment Gateway",
  "total_vulnerabilities": 12,
  "by_severity": {
    "medium": 3,
    "high": 7,
    "critical": 2
  },
  "vulnerabilities": [
    {
      "package": "express",
      "version": "4.18.2",
      "cve": "CVE-2024-29041",
      "severity": "medium",
      "summary": "Open redirect via URL parsing",
      "fixed_in": "4.19.2",
      "is_affected": true
    },
    {
      "package": "flask",
      "version": "2.3.0",
      "cve": "CVE-2023-30861",
      "severity": "high",
      "summary": "Cookie caching on shared proxies allows session hijacking",
      "fixed_in": "2.3.2",
      "is_affected": true
    },
    {
      "package": "django",
      "version": "4.2.7",
      "cve": "CVE-2024-27351",
      "severity": "high",
      "summary": "ReDoS in django.utils.text.Truncator",
      "fixed_in": "4.2.11",
      "is_affected": true
    },
    {
      "package": "jsonwebtoken",
      "version": "8.5.1",
      "cve": "CVE-2022-23529",
      "severity": "critical",
      "summary": "Insecure key retrieval allows JWT forgery",
      "fixed_in": "9.0.0",
      "is_affected": true
    },
    {
      "package": "scikit-learn",
      "version": "0.23.2",
      "cve": "CVE-2020-28975",
      "severity": "medium",
      "summary": "Denial of service via malicious pickle model",
      "fixed_in": "0.24.0",
      "is_affected": true
    },
    {
      "package": "axios",
      "version": "1.4.0",
      "cve": "CVE-2023-45857",
      "severity": "high",
      "summary": "CSRF token exposure via XSRF-TOKEN cookie",
      "fixed_in": "1.6.0",
      "is_affected": true
    },
    {
      "package": "pytorch",
      "version": "1.13.0",
      "cve": "CVE-2024-31583",
      "severity": "high",
      "summary": "Arbitrary code execution via torch.load with pickle",
      "fixed_in": "2.2.0",
      "is_affected": true
    },
    {
      "package": "lodash",
      "version": "4.17.20",
      "cve": "CVE-2021-23337",
      "severity": "high",
      "summary": "Command injection via template function",
      "fixed_in": "4.17.21",
      "is_affected": true
    },
    {
      "package": "lodash",
      "version": "4.17.20",
      "cve": "CVE-2020-28500",
      "severity": "medium",
      "summary": "ReDoS in toNumber, trim, trimEnd",
      "fixed_in": "4.17.21",
      "is_affected": true
    },
    {
      "package": "onnx",
      "version": "1.14.0",
      "cve": "CVE-2024-27318",
      "severity": "high",
      "summary": "Directory traversal in ONNX model extraction",
      "fixed_in": "1.16.0",
      "is_affected": true
    },
    {
      "package": "tensorflow",
      "version": "2.11.0",
      "cve": "CVE-2023-25801",
      "severity": "critical",
      "summary": "OOB read in TFLite GPU delegate",
      "fixed_in": "2.12.0",
      "is_affected": true
    },
    {
      "package": "tensorflow",
      "version": "2.11.0",
      "cve": "CVE-2023-25660",
      "severity": "high",
      "summary": "Heap buffer overflow in AvgPool3DGrad",
      "fixed_in": "2.12.0",
      "is_affected": true
    }
  ],
  "finding_correlation": {
    "matched_findings_count": 0,
    "matched_findings": [],
    "known_vuln_matches": 12,
    "known_vulnerabilities": [
      {
        "package": "express",
        "version": "4.18.2",
        "cve": "CVE-2024-29041",
        "severity": "medium",
        "summary": "Open redirect via URL parsing",
        "fixed_in": "4.19.2",
        "is_affected": true
      },
      {
        "package": "flask",
        "version": "2.3.0",
        "cve": "CVE-2023-30861",
        "severity": "high",
        "summary": "Cookie caching on shared proxies allows session hijacking",
        "fixed_in": "2.3.2",
        "is_affected": true
      },
      {
        "package": "django",
        "version": "4.2.7",
        "cve": "CVE-2024-27351",
        "severity": "high",
        "summary": "ReDoS in django.utils.text.Truncator",
        "fixed_in": "4.2.11",
        "is_affected": true
      },
      {
        "package": "jsonwebtoken",
        "version": "8.5.1",
        "cve": "CVE-2022-23529",
        "severity": "critical",
        "summary": "Insecure key retrieval allows JWT forgery",
        "fixed_in": "9.0.0",
        "is_affected": true
      },
      {
        "package": "scikit-learn",
        "version": "0.23.2",
        "cve": "CVE-2020-28975",
        "severity": "medium",
        "summary": "Denial of service via malicious pickle model",
        "fixed_in": "0.24.0",
        "is_affected": true
      },
      {
        "package": "axios",
        "version": "1.4.0",
        "cve": "CVE-2023-45857",
        "severity": "high",
        "summary": "CSRF token exposure via XSRF-TOKEN cookie",
        "fixed_in": "1.6.0",
        "is_affected": true
      },
      {
        "package": "pytorch",
        "version": "1.13.0",
        "cve": "CVE-2024-31583",
        "severity": "high",
        "summary": "Arbitrary code execution via torch.load with pickle",
        "fixed_in": "2.2.0",
        "is_affected": true
      },
      {
        "package": "lodash",
        "version": "4.17.20",
        "cve": "CVE-2021-23337",
        "severity": "high",
        "summary": "Command injection via template function",
        "fixed_in": "4.17.21",
        "is_affected": true
      },
      {
        "package": "lodash",
        "version": "4.17.20",
        "cve": "CVE-2020-28500",
        "severity": "medium",
        "summary": "ReDoS in toNumber, trim, trimEnd",
        "fixed_in": "4.17.21",
        "is_affected": true
      },
      {
        "package": "onnx",
        "version": "1.14.0",
        "cve": "CVE-2024-27318",
        "severity": "high",
        "summary": "Directory traversal in ONNX model extraction",
        "fixed_in": "1.16.0",
        "is_affected": true
      },
      {
        "package": "tensorflow",
        "version": "2.11.0",
        "cve": "CVE-2023-25801",
        "severity": "critical",
        "summary": "OOB read in TFLite GPU delegate",
        "fixed_in": "2.12.0",
        "is_affected": true
      },
      {
        "package": "tensorflow",
        "version": "2.11.0",
        "cve": "CVE-2023-25660",
        "severity": "high",
        "summary": "Heap buffer overflow in AvgPool3DGrad",
        "fixed_in": "2.12.0",
        "is_affected": true
      }
    ],
    "unmatched_components": 16
  }
}

export const sbomLicenses = {
  "product_id": 1,
  "product_name": "Payment Gateway",
  "total_licenses": 16,
  "unique_licenses": 5,
  "distribution": {
    "MIT": 7,
    "BSD-3-Clause": 5,
    "AGPL-3.0": 1,
    "Apache-2.0": 2,
    "GPL-3.0": 1
  },
  "categories": {
    "permissive": 14,
    "copyleft": 2,
    "weak_copyleft": 0,
    "other": 0
  },
  "risks": [
    {
      "package": "mongo-connector",
      "version": "3.1.1",
      "license": "AGPL-3.0",
      "risk_type": "copyleft",
      "severity": "high",
      "detail": "License 'AGPL-3.0' may impose copyleft obligations on proprietary / commercial software."
    },
    {
      "package": "readline",
      "version": "8.2.0",
      "license": "GPL-3.0",
      "risk_type": "copyleft",
      "severity": "medium",
      "detail": "License 'GPL-3.0' may impose copyleft obligations on proprietary / commercial software."
    }
  ],
  "is_compliant": false,
  "compliance_status": "review_required"
}

export const sbomSupplyChainRisks = {
  "product_id": 1,
  "product_name": "Payment Gateway",
  "total_components_analyzed": 16,
  "overall_risk_level": "high",
  "malicious_packages": [],
  "typosquatting_candidates": [
    {
      "package": "pytorch",
      "similar_to": "torch",
      "similarity": 0.833,
      "severity": "high",
      "detail": "'pytorch' is suspiciously similar to popular package 'torch'."
    }
  ],
  "suspicious_install_scripts": [],
  "low_reputation_packages": [],
  "ml_model_risks": [
    {
      "package": "pytorch",
      "version": "1.13.0",
      "severity": "high",
      "category": "ml_supply_chain",
      "risks": [
        "No model card or provenance documentation found",
        "No integrity hashes provided — cannot verify model has not been tampered with",
        "PyTorch < 2.0 defaults to unsafe pickle deserialization in torch.load()"
      ],
      "recommendation": "Use SafeTensors format where possible. Pin model revisions by hash. Verify model checksums before loading. Avoid pickle deserialization of untrusted models."
    },
    {
      "package": "onnx",
      "version": "1.14.0",
      "severity": "high",
      "category": "ml_supply_chain",
      "risks": [
        "No model card or provenance documentation found",
        "No integrity hashes provided — cannot verify model has not been tampered with"
      ],
      "recommendation": "Use SafeTensors format where possible. Pin model revisions by hash. Verify model checksums before loading. Avoid pickle deserialization of untrusted models."
    },
    {
      "package": "tensorflow",
      "version": "2.11.0",
      "severity": "high",
      "category": "ml_supply_chain",
      "risks": [
        "No model card or provenance documentation found",
        "No integrity hashes provided — cannot verify model has not been tampered with"
      ],
      "recommendation": "Use SafeTensors format where possible. Pin model revisions by hash. Verify model checksums before loading. Avoid pickle deserialization of untrusted models."
    }
  ],
  "total_issues": 4
}

export const copilotStats = {
  "total_cwe_templates": 25,
  "covered_cwes": [
    16,
    20,
    22,
    78,
    79,
    89,
    120,
    190,
    200,
    269,
    287,
    306,
    319,
    327,
    352,
    362,
    434,
    502,
    522,
    601,
    611,
    732,
    798,
    862,
    918
  ],
  "languages_supported": [
    "c",
    "cpp",
    "csharp",
    "dockerfile",
    "golang",
    "html",
    "java",
    "javascript",
    "json",
    "kotlin",
    "php",
    "python",
    "ruby",
    "rust",
    "scala",
    "shell",
    "sql",
    "swift",
    "terraform",
    "typescript",
    "xml",
    "yaml"
  ],
  "severity_levels": [
    "critical",
    "high",
    "medium",
    "low",
    "info"
  ],
  "has_fallback": true
}

export const agentReport = {
  "product_id": 1,
  "overview": {
    "product_name": "Payment Gateway",
    "product_type": "api",
    "business_criticality": "critical",
    "total_findings": 38,
    "risk_level": "high",
    "report_date": "2026-03-21T12:12:16.075683+00:00"
  },
  "risk_summary": {
    "severity_distribution": {
      "critical": 0,
      "high": 29,
      "medium": 9,
      "low": 0,
      "info": 0
    },
    "risk_level": "high",
    "risk_score": 0
  },
  "top_vulnerabilities": [
    {
      "id": 1,
      "title": "python.lang.security.audit.dangerous-subprocess-use",
      "severity": "high",
      "cvss_score": null,
      "cve": null,
      "cwe": 78,
      "component": null,
      "file_path": "app/services/payment_processor.py",
      "status": "active",
      "age_days": 1
    },
    {
      "id": 2,
      "title": "python.lang.security.audit.eval-detected",
      "severity": "high",
      "cvss_score": null,
      "cve": null,
      "cwe": 95,
      "component": null,
      "file_path": "app/utils/config_loader.py",
      "status": "active",
      "age_days": 1
    },
    {
      "id": 3,
      "title": "python.lang.security.audit.sqli.string-concat-query",
      "severity": "high",
      "cvss_score": null,
      "cve": null,
      "cwe": 89,
      "component": null,
      "file_path": "app/api/transactions.py",
      "status": "active",
      "age_days": 1
    },
    {
      "id": 5,
      "title": "python.lang.security.audit.hardcoded-password",
      "severity": "high",
      "cvss_score": null,
      "cve": null,
      "cwe": 798,
      "component": null,
      "file_path": "app/config/settings.py",
      "status": "active",
      "age_days": 1
    },
    {
      "id": 7,
      "title": "python.lang.security.deserialization.avoid-pickle",
      "severity": "high",
      "cvss_score": null,
      "cve": null,
      "cwe": 502,
      "component": null,
      "file_path": "app/services/cache_manager.py",
      "status": "active",
      "age_days": 1
    },
    {
      "id": 43,
      "title": "python.lang.security.audit.dangerous-system-call",
      "severity": "high",
      "cvss_score": null,
      "cve": null,
      "cwe": 78,
      "component": null,
      "file_path": "src/api/admin/execute.py",
      "status": "active",
      "age_days": 0
    },
    {
      "id": 44,
      "title": "python.lang.security.audit.sqli",
      "severity": "high",
      "cvss_score": null,
      "cve": null,
      "cwe": 89,
      "component": null,
      "file_path": "src/services/user_service.py",
      "status": "active",
      "age_days": 0
    },
    {
      "id": 46,
      "title": "python.lang.security.deserialization.avoid-pickle",
      "severity": "high",
      "cvss_score": null,
      "cve": null,
      "cwe": 502,
      "component": null,
      "file_path": "src/ml/model_loader.py",
      "status": "active",
      "age_days": 0
    },
    {
      "id": 47,
      "title": "python.lang.security.audit.insecure-hash",
      "severity": "high",
      "cvss_score": null,
      "cve": null,
      "cwe": 327,
      "component": null,
      "file_path": "src/auth/password_handler.py",
      "status": "active",
      "age_days": 0
    },
    {
      "id": 48,
      "title": "python.lang.security.audit.ssrf-requests",
      "severity": "high",
      "cvss_score": null,
      "cve": null,
      "cwe": 918,
      "component": null,
      "file_path": "src/integrations/webhook_sender.py",
      "status": "active",
      "age_days": 0
    },
    {
      "id": 50,
      "title": "python.lang.security.audit.path-traversal",
      "severity": "high",
      "cvss_score": null,
      "cve": null,
      "cwe": 22,
      "component": null,
      "file_path": "src/services/file_service.py",
      "status": "active",
      "age_days": 0
    },
    {
      "id": 52,
      "title": "python.lang.security.audit.insecure-jwt",
      "severity": "high",
      "cvss_score": null,
      "cve": null,
      "cwe": 287,
      "component": null,
      "file_path": "src/auth/token_service.py",
      "status": "active",
      "age_days": 0
    },
    {
      "id": 72,
      "title": "Secret Detected: aws-access-key-id",
      "severity": "high",
      "cvss_score": null,
      "cve": null,
      "cwe": null,
      "component": null,
      "file_path": "src/config/aws.py",
      "status": "active",
      "age_days": 0
    },
    {
      "id": 73,
      "title": "Secret Detected: generic-api-key",
      "severity": "high",
      "cvss_score": null,
      "cve": null,
      "cwe": null,
      "component": null,
      "file_path": "src/integrations/stripe_client.py",
      "status": "active",
      "age_days": 0
    },
    {
      "id": 74,
      "title": "Secret Detected: private-key",
      "severity": "high",
      "cvss_score": null,
      "cve": null,
      "cwe": null,
      "component": null,
      "file_path": "deploy/ssl/server.key",
      "status": "active",
      "age_days": 0
    }
  ],
  "trend_analysis": [
    {
      "month": "2026-03",
      "counts": {
        "critical": 0,
        "high": 29,
        "medium": 9,
        "low": 0,
        "info": 0
      }
    }
  ],
  "compliance_gaps": {
    "OWASP Top 10": {
      "A02 - Cryptographic Failures": {
        "matched_cwes": [
          319,
          327
        ],
        "finding_count": 4
      },
      "A03 - Injection": {
        "matched_cwes": [
          78,
          79,
          89
        ],
        "finding_count": 9
      },
      "A07 - Auth Failures": {
        "matched_cwes": [
          287
        ],
        "finding_count": 2
      },
      "A08 - Data Integrity Failures": {
        "matched_cwes": [
          502
        ],
        "finding_count": 3
      },
      "A10 - SSRF": {
        "matched_cwes": [
          918
        ],
        "finding_count": 2
      }
    },
    "SANS Top 25": {
      "XSS": {
        "matched_cwes": [
          79
        ],
        "finding_count": 3
      },
      "SQL Injection": {
        "matched_cwes": [
          89
        ],
        "finding_count": 3
      },
      "OS Command Injection": {
        "matched_cwes": [
          78
        ],
        "finding_count": 3
      },
      "Path Traversal": {
        "matched_cwes": [
          22
        ],
        "finding_count": 2
      },
      "CSRF": {
        "matched_cwes": [
          352
        ],
        "finding_count": 2
      }
    }
  },
  "recommendations": [
    {
      "priority": 1,
      "action": "Schedule remediation of 29 high-severity findings in the next sprint.",
      "effort": "high",
      "impact": "high",
      "rationale": "High-severity findings should be addressed within 1-2 weeks to maintain acceptable risk levels."
    },
    {
      "priority": 2,
      "action": "Expand security tooling — fewer than 3 tool types in use.",
      "effort": "medium",
      "impact": "medium",
      "rationale": "A comprehensive AppSec program should include SAST, DAST, SCA, and secrets scanning."
    }
  ],
  "next_steps": [
    "Plan sprint work to address 29 high-severity findings.",
    "Review compliance gaps and map remediation to framework requirements."
  ]
}

export const agentAttackChains = {
  "product_id": 1,
  "attack_chains": [],
  "count": 0
}

export const llmScannerOverview = {
  "org_ai_risk_level": "high",
  "total_products": 5,
  "total_ai_findings": 11,
  "severity_breakdown": {
    "critical": 0,
    "high": 8,
    "medium": 3,
    "low": 0,
    "info": 0
  },
  "exposure_distribution": {
    "critical": 0,
    "high": 2,
    "medium": 1,
    "low": 1,
    "none": 1
  },
  "product_summaries": [
    {
      "product_id": 3,
      "product_name": "Infrastructure Platform",
      "ai_exposure_level": "high",
      "total_ai_findings": 5,
      "prompt_injection_risk": "low",
      "model_supply_chain_risk": "medium"
    },
    {
      "product_id": 1,
      "product_name": "Payment Gateway",
      "ai_exposure_level": "high",
      "total_ai_findings": 3,
      "prompt_injection_risk": "low",
      "model_supply_chain_risk": "medium"
    },
    {
      "product_id": 4,
      "product_name": "Mobile Banking App",
      "ai_exposure_level": "medium",
      "total_ai_findings": 2,
      "prompt_injection_risk": "low",
      "model_supply_chain_risk": "medium"
    },
    {
      "product_id": 5,
      "product_name": "Internal Admin Dashboard",
      "ai_exposure_level": "low",
      "total_ai_findings": 1,
      "prompt_injection_risk": "low",
      "model_supply_chain_risk": "medium"
    },
    {
      "product_id": 2,
      "product_name": "Customer Portal",
      "ai_exposure_level": "none",
      "total_ai_findings": 0,
      "prompt_injection_risk": "low",
      "model_supply_chain_risk": "low"
    }
  ],
  "top_recommendations": [
    "Consider deploying an AI firewall or gateway to monitor and filter LLM inputs/outputs across products."
  ]
}

export const llmScannerProduct = {
  "product_id": 1,
  "ai_exposure_level": "high",
  "prompt_injection_risk": "low",
  "data_poisoning_risk": "low",
  "model_supply_chain_risk": "medium",
  "total_ai_findings": 3,
  "severity_breakdown": {
    "critical": 0,
    "high": 3,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "recommendations": [
    "Replace pickle/joblib deserialization with safe formats (safetensors, ONNX) to prevent code execution attacks."
  ],
  "product_name": "Payment Gateway"
}

export const llmScannerOwaspLlm = {
  "product_id": 1,
  "total_mapped_findings": 3,
  "categories_affected": 2,
  "categories": [
    {
      "code": "LLM01",
      "title": "Prompt Injection",
      "description": "Manipulating LLMs via crafted inputs to cause unintended actions.",
      "finding_count": 0,
      "findings": [],
      "risk_level": "none"
    },
    {
      "code": "LLM02",
      "title": "Insecure Output Handling",
      "description": "Insufficient validation of LLM outputs leading to downstream security issues.",
      "finding_count": 0,
      "findings": [],
      "risk_level": "none"
    },
    {
      "code": "LLM03",
      "title": "Training Data Poisoning",
      "description": "Manipulation of training data to introduce vulnerabilities or biases.",
      "finding_count": 0,
      "findings": [],
      "risk_level": "none"
    },
    {
      "code": "LLM04",
      "title": "Model Denial of Service",
      "description": "Resource-heavy operations causing service degradation via AI models.",
      "finding_count": 0,
      "findings": [],
      "risk_level": "none"
    },
    {
      "code": "LLM05",
      "title": "Supply Chain Vulnerabilities",
      "description": "Compromised components in the AI/ML supply chain.",
      "finding_count": 2,
      "findings": [
        {
          "finding_id": 46,
          "title": "python.lang.security.deserialization.avoid-pickle",
          "severity": "high"
        },
        {
          "finding_id": 7,
          "title": "python.lang.security.deserialization.avoid-pickle",
          "severity": "high"
        }
      ],
      "risk_level": "high"
    },
    {
      "code": "LLM06",
      "title": "Sensitive Information Disclosure",
      "description": "Exposure of confidential data through LLM responses or training data.",
      "finding_count": 0,
      "findings": [],
      "risk_level": "none"
    },
    {
      "code": "LLM07",
      "title": "Insecure Plugin Design",
      "description": "LLM plugins with insecure inputs or insufficient access control.",
      "finding_count": 0,
      "findings": [],
      "risk_level": "none"
    },
    {
      "code": "LLM08",
      "title": "Excessive Agency",
      "description": "Granting too much autonomy to LLM-based systems.",
      "finding_count": 0,
      "findings": [],
      "risk_level": "none"
    },
    {
      "code": "LLM09",
      "title": "Overreliance",
      "description": "Uncritical dependence on LLM outputs without oversight.",
      "finding_count": 1,
      "findings": [
        {
          "finding_id": 47,
          "title": "python.lang.security.audit.insecure-hash",
          "severity": "high"
        }
      ],
      "risk_level": "high"
    },
    {
      "code": "LLM10",
      "title": "Model Theft",
      "description": "Unauthorized access or extraction of proprietary LLM models.",
      "finding_count": 0,
      "findings": [],
      "risk_level": "none"
    }
  ],
  "product_name": "Payment Gateway"
}

export const users = {
  "detail": "Insufficient permissions. Required: users:read"
}

export const notificationSettings = {
  "slack_webhook_url": null,
  "notify_on_new_findings": true,
  "notify_on_scan_complete": true,
  "minimum_severity": "high",
  "slack_configured": false
}

export const jiraStatus = {
  "connected": false,
  "error": "Jira credentials not configured"
}

