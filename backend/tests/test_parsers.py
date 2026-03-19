import json
import pytest
from app.parsers.trivy import TrivyParser
from app.parsers.semgrep import SemgrepParser
from app.parsers.snyk import SnykParser
from app.parsers.gitleaks import GitleaksParser
from app.parsers.bandit import BanditParser
from app.parsers.nuclei import NucleiParser
from app.parsers.generic import GenericParser


class TestTrivyParser:
    def test_parse_vulnerabilities(self):
        data = {
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.20",
                            "FixedVersion": "4.17.21",
                            "Severity": "HIGH",
                            "Description": "Prototype pollution in lodash",
                        }
                    ],
                }
            ]
        }
        parser = TrivyParser()
        findings = parser.parse(json.dumps(data).encode())
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert "lodash" in findings[0]["title"]
        assert findings[0]["cve"] == "CVE-2023-1234"

    def test_parse_misconfigurations(self):
        data = {
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        {
                            "ID": "DS002",
                            "Title": "Root user",
                            "Description": "Running as root",
                            "Severity": "HIGH",
                            "Resolution": "Use non-root user",
                        }
                    ],
                }
            ]
        }
        parser = TrivyParser()
        findings = parser.parse(json.dumps(data).encode())
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_parse_empty(self):
        data = {"Results": []}
        parser = TrivyParser()
        findings = parser.parse(json.dumps(data).encode())
        assert len(findings) == 0


class TestSemgrepParser:
    def test_parse(self):
        data = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.exec-detected",
                    "path": "app/utils.py",
                    "start": {"line": 42},
                    "extra": {
                        "message": "Detected use of exec",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-78"]},
                    },
                }
            ]
        }
        parser = SemgrepParser()
        findings = parser.parse(json.dumps(data).encode())
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["file_path"] == "app/utils.py"
        assert findings[0]["line_number"] == 42
        assert findings[0]["cwe"] == 78


class TestSnykParser:
    def test_parse(self):
        data = {
            "vulnerabilities": [
                {
                    "title": "Remote Code Execution",
                    "severity": "critical",
                    "cvssScore": 9.8,
                    "packageName": "log4j-core",
                    "version": "2.14.1",
                    "identifiers": {"CVE": ["CVE-2021-44228"], "CWE": ["CWE-502"]},
                    "id": "SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314720",
                }
            ]
        }
        parser = SnykParser()
        findings = parser.parse(json.dumps(data).encode())
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"
        assert findings[0]["cve"] == "CVE-2021-44228"
        assert findings[0]["component"] == "log4j-core"


class TestGitleaksParser:
    def test_parse(self):
        data = [
            {
                "RuleID": "aws-access-key",
                "Description": "AWS Access Key",
                "File": "config.py",
                "StartLine": 15,
                "Fingerprint": "abc123",
            }
        ]
        parser = GitleaksParser()
        findings = parser.parse(json.dumps(data).encode())
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert "aws-access-key" in findings[0]["title"]


class TestBanditParser:
    def test_parse(self):
        data = {
            "results": [
                {
                    "test_id": "B101",
                    "test_name": "assert_used",
                    "issue_text": "Use of assert detected",
                    "issue_severity": "LOW",
                    "filename": "tests/test_app.py",
                    "line_number": 10,
                    "issue_cwe": {"id": 703},
                }
            ]
        }
        parser = BanditParser()
        findings = parser.parse(json.dumps(data).encode())
        assert len(findings) == 1
        assert findings[0]["severity"] == "low"
        assert findings[0]["cwe"] == 703


class TestNucleiParser:
    def test_parse_jsonl(self):
        lines = [
            json.dumps({
                "template-id": "cve-2023-1234",
                "host": "https://example.com",
                "matched-at": "https://example.com/admin",
                "info": {
                    "name": "Admin Panel Exposed",
                    "severity": "medium",
                    "description": "Admin panel is publicly accessible",
                    "classification": {"cve-id": ["CVE-2023-1234"]},
                },
            })
        ]
        parser = NucleiParser()
        findings = parser.parse("\n".join(lines).encode())
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"
        assert findings[0]["cve"] == "CVE-2023-1234"


class TestGenericParser:
    def test_parse_json(self):
        data = [
            {
                "title": "SQL Injection",
                "severity": "high",
                "file_path": "app/db.py",
                "line_number": 55,
                "cve": "CVE-2023-9999",
            }
        ]
        parser = GenericParser()
        findings = parser.parse(json.dumps(data).encode())
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_parse_csv(self):
        csv_content = "title,severity,file_path\nXSS Attack,medium,templates/page.html\n"
        parser = GenericParser()
        findings = parser.parse(csv_content.encode())
        assert len(findings) == 1
        assert findings[0]["title"] == "XSS Attack"
        assert findings[0]["severity"] == "medium"
