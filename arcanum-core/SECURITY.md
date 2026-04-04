# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.x.x  | Yes       |
| < 3.0   | No       |

## Reporting a Vulnerability

If you discover a security vulnerability in Arcanum Core itself (not in a target you're testing), please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email security concerns to the maintainers via GitHub private vulnerability reporting
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix**: Within 2 weeks for critical issues

## Scope

The following are in scope for security reports:

- Command injection in the Arcanum application itself
- Sandbox escape vulnerabilities
- Authentication/authorization bypass in the Web UI
- Sensitive data exposure (credentials, tokens)
- Dependency vulnerabilities with exploitable impact

## Responsible Use

Arcanum Core is a security testing tool. Users are responsible for:

- Obtaining proper authorization before testing any target
- Following all applicable laws and regulations
- Responsible disclosure of vulnerabilities found during testing
- Never using this tool against systems without explicit permission

## Sandbox Security

The Docker sandbox is designed with defense-in-depth:

- Runs as non-root user (`nobody`)
- Memory limited to 4GB
- `no-new-privileges` security option
- Optional network isolation
- No privileged mode

Report any sandbox escape vectors as critical vulnerabilities.
