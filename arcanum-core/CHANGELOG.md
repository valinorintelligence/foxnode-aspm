# Changelog

All notable changes to Arcanum Core will be documented in this file.

## [3.0.0] - 2026-04-03

### Added
- **Agent Engine** with Ollama LLM integration, extended thinking (`<think>` blocks), phase checkpoints (RECON → ANALYSIS → EXPLOIT → REPORT), context compression, and self-evaluation
- **8 Native Tools**: execute (sandbox), browser_action (Playwright), web_search, create_file, read_file, create_finding, search_cve, stash_artifact
- **40-Tool Arsenal** across 7 categories: Recon, Web, Network, Credentials, Exploitation, Post-Exploitation, OSINT
- **57-Skill System** with keyword auto-mapping (289 keywords) covering recon, web, network, creds, exploit, post, osint, and CTF categories
- **3 Interaction Modes**: Autopilot (fully autonomous), Copilot (AI suggests with risk assessment), Manual (user drives, AI advises)
- **Deep Recon Autostart**: bare domain input auto-expands to full reconnaissance pipeline
- **Textual TUI** with tabbed tool panels, findings sidebar, stash panel, F-key shortcuts
- **FastAPI Backend** with REST API endpoints for sessions, tools, findings, stash, CVE, reports
- **WebSocket Streaming** for real-time agent output
- **Alpine.js + Tailwind Web UI** with dark hacker aesthetic, particle system, grid overlay, scan lines
- **Docker Sandbox** (Kali Linux) for isolated tool execution with memory limits and no-new-privileges
- **SQLite Persistence** for sessions, findings, and stash artifacts
- **CVE Knowledge Base** with FTS5 full-text search and NVD import
- **Cross-Operation Stash** for sharing credentials, hosts, payloads, tokens between engagements
- **Report Generation** in PDF, HTML, Markdown, JSON with CVSS scoring
- **Multi-Language Reports** in English, Spanish, Chinese, Japanese, Korean
- **YAML Workflow Templates**: full_recon, web_assessment, network_pentest, bug_bounty, api_security
- **Real-Time Alert Engine** with regex pattern matching for critical findings
- **Vulnerability Deduplication** via Jaccard similarity (0.7 threshold)
- **Model Tier Auto-Detection** based on system RAM (Small/Medium/Large/XLarge)
- **Risk Assessment** for Copilot mode tool suggestions (LOW/MEDIUM/HIGH)
- **Docker Compose** for full-stack deployment (Arcanum + Ollama + Sandbox)
- **CI/CD** with GitHub Actions (test, lint, Docker build, PyPI publish)
