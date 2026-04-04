<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.0-cyan?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/tools-40+-red?style=for-the-badge" alt="Tools">
  <img src="https://img.shields.io/badge/skills-57-purple?style=for-the-badge" alt="Skills">
  <img src="https://img.shields.io/badge/cloud-0%20dependencies-orange?style=for-the-badge" alt="Cloud">
</p>

<h1 align="center">ARCANUM CORE</h1>
<h3 align="center">Autonomous AI-Powered Security Reconnaissance Platform</h3>

<p align="center">
  <em>Self-hosted LLM + 40+ pentesting tools + Docker sandbox + Zero cloud dependencies</em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#interaction-modes">Modes</a> •
  <a href="#tool-arsenal">Tools</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#web-ui">Web UI</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## What is Arcanum Core?

Arcanum Core is an open-source, autonomous security reconnaissance and penetration testing platform that combines a **self-hosted LLM** (via Ollama) with an **isolated execution environment** (Docker/Kali). It delivers a rich **Terminal TUI**, a **Web UI**, and integrates **40+ professional pentesting tools** with AI-driven automation.

**No API keys. No cloud. No content filtering. Everything runs locally.**

```
> arcanum autopilot example.com

[AUTOPILOT] Starting full engagement on example.com
[RECON] Running subdomain enumeration...
[RECON] Found 47 subdomains → 23 live hosts
[SCAN] Port scanning 23 hosts...
[VULN] Running nuclei → 3 critical, 7 high findings
[EXPLOIT] Confirmed SQLi on /api/login (CVSS 9.8)
[REPORT] Generated report with 4 verified vulnerabilities
```

---

## Features

### Core Platform
- **3 Interaction Modes** — Autopilot (fully autonomous), Copilot (AI suggests with risk levels, you approve), Manual (you drive, AI advises)
- **40+ Security Tools** — Integrated across 7 categories with dedicated UI tabs
- **57 Skills** — Keyword-mapped playbooks with 289 auto-mapped keywords
- **Self-Hosted LLM** — Ollama-based, runs on Apple Silicon / NVIDIA GPUs
- **Isolated Sandbox** — Kali Linux Docker container with memory limits and security hardening

### AI Agent Engine
- **Extended Thinking** — `<think>` block support for complex reasoning
- **Phase Checkpoints** — RECON → ANALYSIS → EXPLOIT → REPORT with auto-evaluation
- **Context Compression** — Automatic context windowing every 15 iterations to prevent OOM
- **Self-Evaluation** — Agent reviews its own progress every 10 iterations
- **Deep Recon Autostart** — Bare domain input auto-expands to full recon pipeline
- **Vulnerability Deduplication** — Jaccard similarity (0.7 threshold) prevents duplicate findings
- **Risk Assessment** — Copilot mode rates each action LOW/MEDIUM/HIGH

### Dual Interface
- **Terminal TUI** — Textual-based with tabbed tool panels, findings sidebar, stash, F-key shortcuts
- **Web UI** — Alpine.js + Tailwind with dark hacker aesthetic, particle system, real-time WebSocket streaming

### Data & Reporting
- **Persistent Ops** — Named workspaces per engagement with SQLite-backed sessions
- **Cross-Op Stash** — Share credentials, hosts, payloads, tokens between operations
- **CVE Knowledge Base** — 250K+ CVEs with FTS5 full-text search
- **Report Generation** — PDF, HTML, Markdown, JSON with CVSS scoring
- **5-Language Reports** — English, Spanish, Chinese, Japanese, Korean
- **Real-Time Alerts** — Pattern-matching alert engine for critical findings

### Workflow Automation
- **YAML Templates** — Reusable methodology definitions (full_recon, web_assessment, network_pentest, bug_bounty, api_security)
- **Model Tier Auto-Detection** — Recommends optimal model based on system RAM
- **CI/CD** — GitHub Actions for testing, linting, Docker builds, PyPI publishing

---

## Quick Start

### Prerequisites
- Python 3.11+
- Docker
- [Ollama](https://ollama.ai) with a 30B+ parameter model

### Installation

```bash
# Install from source
git clone https://github.com/valinorintelligence/arcanum-core.git
cd arcanum-core
pip install -e .

# Pull recommended model
ollama pull qwen3:32b

# Check system requirements
arcanum doctor

# Build the sandbox
arcanum sandbox build
```

### Launch

```bash
# Full autonomous assessment
arcanum autopilot example.com

# AI-assisted with approval on each step
arcanum copilot example.com

# Manual mode with AI advice
arcanum manual

# Start Web UI
arcanum serve --port 8000
```

---

## Interaction Modes

### Autopilot — Full Autonomous Operation
Give a target, watch it work. The agent chains tools through all phases automatically.

```
> arcanum autopilot example.com

[PHASE: RECON] Subdomain enumeration → 47 subdomains found
[PHASE: RECON] DNS resolution → 23 live hosts
[PHASE: ANALYSIS] Nuclei scan → CVE-2024-4577 (Critical, CVSS 9.8)
[PHASE: EXPLOIT] SQL injection confirmed on /api/login
[PHASE: REPORT] 4 findings, report generated
```

### Copilot — AI Suggests, You Approve
Each action is explained with risk level before execution.

```
[SUGGEST] Run nuclei with critical templates
          Risk: MEDIUM | Duration: ~5m | Stealth: Active
          [Y]es / [N]o / [M]odify? y
```

### Manual — You Drive, AI Advises
Full control with expert guidance on demand.

```
> What's the best way to test for SSRF here?

[ADVICE] Based on the parameters I found on /api/fetch:
1. Test with internal IPs: 127.0.0.1, 169.254.169.254
2. Try DNS rebinding with your own domain
3. Use out-of-band detection with webhook.site
```

---

## Tool Arsenal (40 Tools)

| Category | Tools | Count |
|----------|-------|-------|
| **Reconnaissance** | subfinder, dnsx, nmap, masscan, httpx, katana, theHarvester | 7 |
| **Web Application** | nuclei, sqlmap, dalfox, feroxbuster, ffuf, arjun, wpscan, testssl, graphqlmap, jwt_tool | 10 |
| **Network & AD** | netexec, snmpwalk, tshark, bettercap, chisel | 5 |
| **Credentials** | hashcat, hydra, haiti, trufflehog, seclists | 5 |
| **Exploitation** | metasploit, pwncat, pwntools, sliver | 4 |
| **Post-Exploit** | linpeas, winpeas, impacket, bloodhound, mimikatz | 5 |
| **OSINT** | sherlock, holehe, exiftool, gowitness | 4 |

---

## Skill System (57 Skills)

Auto-mapped playbooks with 289 keywords across 8 categories:

| Category | Skills | Examples |
|----------|--------|----------|
| Recon | 10 | subdomain_enum, port_scan, web_crawl, tech_fingerprint |
| Web | 12 | sqli_test, xss_test, dir_bruteforce, cors_test, ssrf_test |
| Network | 6 | smb_enum, ad_enum, mitm_attack, tunnel_setup |
| Credentials | 5 | hash_crack, brute_force, secret_scan, default_creds |
| Exploitation | 5 | metasploit_exploit, reverse_shell, privesc_check |
| Post-Exploit | 4 | linux_privesc, credential_dump, ad_attack_path |
| OSINT | 5 | username_osint, email_osint, google_dork |
| CTF | 5 | ctf_web, ctf_crypto, ctf_forensics, ctf_pwn |

---

## Architecture

```
arcanum-core/
├── arcanum/
│   ├── agent/          # AI engine, LLM client, skills, orchestrator
│   │   ├── engine.py   # Agent loop with thinking, phases, compression
│   │   ├── llm.py      # Ollama client with model detection
│   │   ├── tools.py    # 8 native tools with real implementations
│   │   ├── skills.py   # 57 skills with keyword auto-mapping
│   │   └── orchestrator.py  # Multi-tool workflow execution
│   ├── api/            # FastAPI + WebSocket backend
│   ├── cli/            # Textual TUI with 3 modes
│   ├── core/           # Config, DB, CVE KB, stash, reports, i18n, alerts
│   │   ├── config.py   # Model tier auto-detection
│   │   ├── workflows.py # YAML workflow templates
│   │   ├── i18n.py     # 5-language translations
│   │   └── reports.py  # PDF/HTML/MD/JSON generation
│   ├── sandbox/        # Docker + Playwright browser
│   └── tools/          # 40-tool registry (registry.json)
├── frontend/           # Alpine.js + Tailwind Web UI
├── docker/             # Kali sandbox + app Dockerfiles
└── tests/              # Unit + integration tests
```

### Model Tier Recommendations

| Tier | RAM | Model | Parameters |
|------|-----|-------|------------|
| Small | 8-16 GB | qwen3:30b-a3b | 30B (3B active MoE) |
| Medium | 16-64 GB | qwen3:32b | 32B |
| Large | 64-192 GB | qwen3.5:122b | 122B (10B active MoE) |
| X-Large | 192+ GB | qwen3.5:400b | 397B (17B active MoE) |

---

## Web UI

The Web UI provides a dark-themed dashboard with:
- Real-time WebSocket streaming of agent output
- Dashboard with active ops, findings, stash stats
- Tool category tabs (Recon, Web, Network, Creds, Exploit, Post, OSINT)
- Findings viewer with severity badges and CVSS scores
- Stash manager for cross-operation artifacts
- Report generator with format selection
- CVE search interface
- Particle animation background with grid overlay

```bash
arcanum serve --port 8000
# Open http://localhost:8000
```

---

## CLI Commands

```bash
# Modes
arcanum autopilot <target>          # Full autonomous assessment
arcanum copilot <target>            # AI-assisted with approval
arcanum manual                      # Manual mode with AI advice

# Operations
arcanum ops list                    # List all operations
arcanum ops new <name> -t <target>  # Create new operation
arcanum ops resume <name>           # Resume operation
arcanum ops delete <name>           # Delete operation

# Stash
arcanum stash list                  # List stashed artifacts
arcanum stash add <type> <value>    # Add artifact
arcanum stash pull <id>             # Pull artifact

# CVE
arcanum cve search <query>          # Search CVE knowledge base
arcanum cve update                  # Update from NVD feeds

# Server
arcanum serve --port 8000           # Start Web UI

# Utilities
arcanum doctor                      # System requirements check
arcanum sandbox build               # Build Docker sandbox image
```

### Keyboard Shortcuts (TUI)

| Key | Action |
|-----|--------|
| F1 | Help |
| F2 | Workspace |
| F3 | Stash |
| F4 | CVE Search |
| F5 | Switch Mode |
| F9 | Generate Report |
| F10 | Quit |

---

## Configuration

Environment variables (prefix `ARCANUM_`):

```bash
# LLM
ARCANUM_OLLAMA_URL=http://localhost:11434
ARCANUM_OLLAMA_MODEL=qwen3:32b
ARCANUM_OLLAMA_NUM_CTX=131072
ARCANUM_OLLAMA_TEMPERATURE=0.15
ARCANUM_OLLAMA_ENABLE_THINKING=true

# Sandbox
ARCANUM_SANDBOX_IMAGE=arcanum-sandbox:latest
ARCANUM_COMMAND_TIMEOUT=900

# Agent
ARCANUM_DEEP_RECON_AUTOSTART=true
ARCANUM_ALLOW_DESTRUCTIVE_TESTING=false
ARCANUM_VULN_SIMILARITY_THRESHOLD=0.7
```

---

## Docker Deployment

```bash
cd docker
docker compose up -d

# This starts:
# - Arcanum Core (port 8000)
# - Ollama (port 11434)
# - Kali Sandbox (isolated)
```

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest --cov=arcanum -v

# Lint
ruff check arcanum/

# Type check
mypy arcanum/
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Key areas:
- Adding new tools to the registry
- Creating skills and workflow templates
- Adding language translations
- Improving the agent engine

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Ethical Use

Arcanum Core is designed exclusively for **authorized security testing**:
- Penetration testing with written authorization
- Bug bounty programs within defined scope
- CTF competitions and security education
- Security research on owned systems

**Never use this tool against systems without explicit permission.**

---

<p align="center">
  <strong>Arcanum Core</strong> — Open Source AI Security Reconnaissance<br>
  <em>Built with Claude Code • MIT License</em>
</p>
