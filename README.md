<p align="center">
  <img src="docs/images/architecture-flowchart.svg" alt="FoxNode ASPM Architecture" width="100%"/>
</p>

<h1 align="center">FoxNode ASPM</h1>
<p align="center"><strong>Open-source Application Security Posture Management Platform</strong></p>

<p align="center">
  <a href="https://github.com/valinorintelligence/foxnode-aspm/releases"><img src="https://img.shields.io/github/v/release/valinorintelligence/foxnode-aspm?style=flat-square&color=0c8ee9" alt="Release"></a>
  <a href="https://github.com/valinorintelligence/foxnode-aspm/blob/main/LICENSE"><img src="https://img.shields.io/github/license/valinorintelligence/foxnode-aspm?style=flat-square&color=10b981" alt="License"></a>
  <a href="https://github.com/valinorintelligence/foxnode-aspm/stargazers"><img src="https://img.shields.io/github/stars/valinorintelligence/foxnode-aspm?style=flat-square&color=f59e0b" alt="Stars"></a>
  <a href="https://github.com/valinorintelligence/foxnode-aspm/issues"><img src="https://img.shields.io/github/issues/valinorintelligence/foxnode-aspm?style=flat-square&color=ef4444" alt="Issues"></a>
  <img src="https://img.shields.io/badge/python-3.12+-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/react-18-61dafb?style=flat-square&logo=react&logoColor=white" alt="React">
  <img src="https://img.shields.io/badge/docker-ready-2496ed?style=flat-square&logo=docker&logoColor=white" alt="Docker">
</p>

<p align="center">
  <a href="https://foxnode-aspm.vercel.app/login"><img src="https://img.shields.io/badge/🚀_Live_Demo-Try_Now-10b981?style=for-the-badge" alt="Live Demo"></a>
</p>

<p align="center">
  <a href="https://foxnode-aspm.vercel.app/login">Live Demo</a> &nbsp;·&nbsp;
  <a href="#-quick-start">Quick Start</a> &nbsp;·&nbsp;
  <a href="#-features">Features</a> &nbsp;·&nbsp;
  <a href="#-screenshots">Screenshots</a> &nbsp;·&nbsp;
  <a href="#-supported-scanners">Scanners</a> &nbsp;·&nbsp;
  <a href="#-architecture">Architecture</a> &nbsp;·&nbsp;
  <a href="#-api-documentation">API Docs</a> &nbsp;·&nbsp;
  <a href="#-contributing">Contributing</a>
</p>

---

## What is FoxNode ASPM?

FoxNode ASPM is a modern, developer-friendly platform for managing application security vulnerabilities across your entire software portfolio. It aggregates findings from **16+ security scanners**, deduplicates them intelligently, and provides actionable dashboards to track your security posture.

> Built from the ground up with **React 18**, **TailwindCSS** with dark/light theme toggle, **FastAPI** async backend, and first-class integrations with **Jira** and **Slack**.

---

## 📸 Screenshots

### Security Dashboard
> Real-time overview of your application security posture with severity distribution, scanner breakdown, and risk trends.

<p align="center">
  <img src="docs/images/screenshots/dashboard.png" alt="Security Dashboard — Dark Mode" width="100%" style="border-radius: 8px;"/>
</p>

### Dark & Light Theme
> Toggle between dark and light modes with a single click. Theme preference is persisted across sessions.

<p align="center">
  <img src="docs/images/screenshots/dashboard-light.png" alt="Security Dashboard — Light Mode" width="100%" style="border-radius: 8px;"/>
</p>

### Scan Import — 16+ Scanner Support
> Upload results from Trivy, Semgrep, Snyk, ZAP, Nuclei, Gitleaks, Bandit, Checkov, SonarQube, and more. Supports JSON, CSV, XML, JSONL, and SARIF formats.

<p align="center">
  <img src="docs/images/screenshots/scan-import.png" alt="Scan Import" width="100%" style="border-radius: 8px;"/>
</p>

### AI Finding Triage
> Intelligent prioritization engine with false positive detection, auto-grouping, and contextual scoring to surface what matters most.

<p align="center">
  <img src="docs/images/screenshots/ai-triage.png" alt="AI Finding Triage" width="100%" style="border-radius: 8px;"/>
</p>

### Security Scorecard
> Letter-grade (A–F) security posture scoring per product with org-wide overview, 30-day trend charts, and a product leaderboard.

<p align="center">
  <img src="docs/images/screenshots/scorecard.png" alt="Security Scorecard" width="100%" style="border-radius: 8px;"/>
</p>

### Compliance Mapping
> Map findings to OWASP Top 10, PCI-DSS, SOC 2, CIS Benchmarks, and ISO 27001 with detailed gap analysis and control-level pass/fail status.

<p align="center">
  <img src="docs/images/screenshots/compliance.png" alt="Compliance Mapping" width="100%" style="border-radius: 8px;"/>
</p>

### SLA Tracker & Risk Heatmap
> Monitor remediation timelines, track breach rates, and visualize risk concentration across products and severities.

<p align="center">
  <img src="docs/images/screenshots/sla-tracker.png" alt="SLA Tracker" width="100%" style="border-radius: 8px;"/>
</p>

### Integrations — Jira & Slack
> Create Jira issues directly from findings with auto-mapped severity. Get Slack alerts for new findings and scan completions.

<p align="center">
  <img src="docs/images/screenshots/integrations.png" alt="Integrations" width="100%" style="border-radius: 8px;"/>
</p>

### Security Metrics & KPIs
> Track MTTR, vulnerability aging, burndown charts, scan velocity, and executive-ready security KPI dashboards.

<p align="center">
  <img src="docs/images/screenshots/metrics.png" alt="Security Metrics" width="100%" style="border-radius: 8px;"/>
</p>

### Attack Path Analysis
> Visualize exploitable attack chains across your product portfolio with risk-scored paths and blast radius mapping.

<p align="center">
  <img src="docs/images/screenshots/attack-paths.png" alt="Attack Path Analysis" width="100%" style="border-radius: 8px;"/>
</p>

### AI Security Agent
> Autonomous AI agent that analyzes products, identifies multi-step attack chains, and generates deep security reports.

<p align="center">
  <img src="docs/images/screenshots/security-agent.png" alt="AI Security Agent" width="100%" style="border-radius: 8px;"/>
</p>

### SBOM & Supply Chain Security
> Full software bill of materials with component inventory, license analysis, and supply chain risk scoring.

<p align="center">
  <img src="docs/images/screenshots/sbom.png" alt="SBOM" width="100%" style="border-radius: 8px;"/>
</p>

### AI Remediation Copilot
> Get AI-powered fix recommendations with vulnerable vs. fixed code examples, effort estimates, and prioritized remediation plans.

<p align="center">
  <img src="docs/images/screenshots/copilot.png" alt="AI Copilot" width="100%" style="border-radius: 8px;"/>
</p>

### LLM/AI Security Scanner
> Detect vulnerabilities in AI/ML code including prompt injection, data poisoning, and model supply chain risks mapped to OWASP LLM Top 10.

<p align="center">
  <img src="docs/images/screenshots/llm-scanner.png" alt="LLM Scanner" width="100%" style="border-radius: 8px;"/>
</p>

### Settings & User Management
> RBAC with Admin, Manager, Analyst, and Viewer roles. Configure Jira, Slack, and platform settings.

<p align="center">
  <img src="docs/images/screenshots/settings.png" alt="Settings" width="100%" style="border-radius: 8px;"/>
</p>

<details>
<summary><strong>More Screenshots</strong></summary>

#### Login
<p align="center"><img src="docs/images/screenshots/login.png" alt="Login" width="100%"/></p>

#### Products
<p align="center"><img src="docs/images/screenshots/products.png" alt="Products" width="100%"/></p>

#### Findings
<p align="center"><img src="docs/images/screenshots/findings.png" alt="Findings" width="100%"/></p>

#### Finding Detail
<p align="center"><img src="docs/images/screenshots/finding-detail.png" alt="Finding Detail" width="100%"/></p>

#### Engagements
<p align="center"><img src="docs/images/screenshots/engagements.png" alt="Engagements" width="100%"/></p>

</details>

---

## ✨ Features

### Core Platform
| | Feature | Description |
|---|---------|-------------|
| 🎨 | **Dark & Light Theme** | React 18 + TailwindCSS — toggleable dark/light theme with localStorage persistence |
| 🔍 | **16 Scanner Parsers** | Semgrep, Trivy, Snyk, ZAP, Nuclei, Gitleaks, Bandit, Checkov, SonarQube, Prowler, tfsec, TruffleHog, Dependency-Check, SARIF, and more |
| 🧬 | **Smart Deduplication** | Hash-based dedup prevents duplicate findings across scans |
| 📊 | **Real-time Dashboard** | Severity distribution, scanner breakdown, risk trends, top vulnerable products |
| 📦 | **Product Management** | Organize findings by products, engagements, and test campaigns |
| 🔗 | **Jira Integration** | Create issues from findings with auto-mapped severity, label tagging, and bidirectional status sync |
| 🔔 | **Slack Notifications** | Alerts for new findings and scan completions with configurable severity thresholds |
| 🛡️ | **RBAC** | Admin, Manager, Analyst, and Viewer roles with granular permissions |
| 🐳 | **Docker-Ready** | One-command deployment with Docker Compose |
| ⚡ | **REST API** | Full API for CI/CD pipeline integration |
| 🔄 | **GitHub Actions CI/CD** | Built-in pipelines for lint, test, build, security scan, and Docker publish |

### Advanced Security Intelligence
| | Feature | Description |
|---|---------|-------------|
| 🧠 | **AI Finding Triage** | Intelligent prioritization with false positive detection, auto-grouping, and contextual scoring |
| 🏆 | **Security Scorecard** | Letter-grade (A–F) posture scores per product with trend tracking and leaderboard |
| 📋 | **Compliance Mapping** | Map findings to OWASP Top 10, PCI-DSS, SOC 2, CIS Benchmarks, and ISO 27001 with gap analysis |
| ⏱️ | **SLA Tracker & Risk Heatmap** | Monitor remediation timelines, breach rates, and risk concentration visualization |
| 📈 | **Security Metrics & KPIs** | MTTR, vulnerability aging, burndown charts, scan velocity, and executive dashboards |
| 🕸️ | **Attack Path Analysis** | Visualize exploitable attack chains with risk scoring and blast radius mapping |
| 🤖 | **AI Security Agent** | Autonomous agent for deep product analysis, attack chain discovery, and report generation |
| 📦 | **SBOM & Supply Chain** | Software bill of materials with component inventory, license tracking, and supply chain risk scoring |
| 🔧 | **AI Remediation Copilot** | AI-powered fix recommendations with code examples, effort estimates, and prioritized plans |
| 🔬 | **LLM/AI Security Scanner** | Detect AI/ML vulnerabilities including prompt injection and data poisoning, mapped to OWASP LLM Top 10 |

---

## 🚀 Quick Start

### Using Docker Compose (Recommended)

```bash
git clone https://github.com/valinorintelligence/foxnode-aspm.git
cd foxnode-aspm
cp .env.example .env
docker compose up -d
```

The app will be available at:
| Service | URL |
|---------|-----|
| **Frontend** | http://localhost |
| **API Docs (Swagger)** | http://localhost:8000/docs |
| **API Docs (ReDoc)** | http://localhost:8000/redoc |
| **Health Check** | http://localhost:8000/api/health |

### Local Development

**Backend:**
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

**Prerequisites:**
- Python 3.12+
- Node.js 20+
- PostgreSQL 16+
- Redis 7+

---

## 🔍 Supported Scanners

FoxNode ASPM includes **16 built-in parsers** covering every category of security scanning:

| Category | Tools | Parser Key |
|----------|-------|------------|
| **SAST** | Semgrep, SonarQube, Bandit | `semgrep`, `sonarqube`, `bandit` |
| **DAST** | OWASP ZAP, Nuclei | `zap`, `nuclei` |
| **SCA** | Trivy, Snyk, OWASP Dependency-Check | `trivy`, `snyk`, `dependency_check` |
| **Cloud Security** | Prowler | `prowler` |
| **IaC** | Checkov, tfsec | `checkov`, `tfsec` |
| **Secrets** | Gitleaks, TruffleHog | `gitleaks`, `trufflehog` |
| **Universal** | SARIF format (GitHub CodeQL, etc.) | `sarif` |
| **Generic** | Any tool via JSON/CSV | `generic` |

---

## 📐 Architecture

<p align="center">
  <img src="docs/images/data-flow.svg" alt="FoxNode ASPM Data Flow" width="100%"/>
</p>

```
foxnode-aspm/
├── backend/                  # FastAPI + SQLAlchemy async
│   ├── app/
│   │   ├── api/              # REST endpoints (auth, products, findings, scans, triage, scorecard, compliance, sla, metrics, attack-paths, agent, sbom, copilot, llm-scanner, jira, notifications, users)
│   │   ├── core/             # Config, DB, security, RBAC
│   │   ├── models/           # SQLAlchemy models (User, Product, Finding, Integration, ScanImport)
│   │   ├── parsers/          # 16 scanner result parsers + registry
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   └── services/         # Jira, Notifications, AI Triage, Scorecard, Compliance, SLA, Metrics, Attack Paths, Security Agent, SBOM, Copilot, LLM Scanner services
│   └── requirements.txt
├── frontend/                 # React 18 + TypeScript + Vite + TailwindCSS
│   ├── src/
│   │   ├── components/       # Layout (Sidebar, Header), SeverityBadge
│   │   ├── pages/            # 19 pages: Dashboard, Products, Findings, Engagements, Integrations, ScanImport, Settings, AI Triage, Scorecard, Compliance, SLA Tracker, Metrics, Attack Paths, Security Agent, SBOM, Copilot, LLM Scanner, API Security
│   │   ├── services/         # Axios API client
│   │   └── store/            # Zustand auth + theme state management
│   └── package.json
├── docker/                   # Dockerfiles + nginx config
├── .github/workflows/        # CI/CD pipeline + release workflow
├── docker-compose.yml        # Full stack deployment
└── .env.example              # Configuration template
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 18, TypeScript, Vite, TailwindCSS, Recharts, Zustand, React Query |
| **Backend** | FastAPI, SQLAlchemy (async), Pydantic v2, Celery |
| **Database** | PostgreSQL 16 |
| **Cache** | Redis 7 |
| **Auth** | JWT (python-jose), bcrypt, RBAC |
| **Deployment** | Docker Compose, nginx, GitHub Actions |

---

## 📡 API Documentation

Once running, visit the interactive API docs:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/register` | Create account |
| `POST` | `/api/v1/auth/login` | Get JWT access token |
| `GET` | `/api/v1/dashboard/stats` | Dashboard metrics & charts |
| `GET/POST` | `/api/v1/products` | Manage products |
| `GET/POST` | `/api/v1/findings` | Manage findings |
| `GET` | `/api/v1/findings/:id` | Finding detail with full context |
| `POST` | `/api/v1/scans/import` | Import scan results (multipart) |
| `GET` | `/api/v1/scans/parsers` | List supported parsers |
| `POST` | `/api/v1/jira/create-issue/:findingId` | Create Jira issue from finding |
| `POST` | `/api/v1/notifications/test-slack` | Test Slack webhook |
| `GET/PATCH` | `/api/v1/users` | User management (Admin) |
| `POST` | `/api/v1/triage/analyze/:findingId` | AI triage analysis for a finding |
| `POST` | `/api/v1/triage/bulk-analyze` | Bulk AI triage for a product |
| `GET` | `/api/v1/triage/summary/:productId` | Triage summary with priorities |
| `GET` | `/api/v1/scorecard/overview` | Org-wide security scorecard |
| `GET` | `/api/v1/scorecard/trends` | Score trend data (30 days) |
| `GET` | `/api/v1/compliance/overview` | All frameworks compliance overview |
| `GET` | `/api/v1/compliance/report/:frameworkId` | Detailed compliance report |
| `GET` | `/api/v1/compliance/gaps/:frameworkId` | Gap analysis for framework |
| `GET` | `/api/v1/sla/status` | SLA status summary |
| `GET` | `/api/v1/sla/heatmap` | Risk heatmap (products x severity) |
| `GET` | `/api/v1/sla/breaches` | SLA breached findings |
| `GET` | `/api/v1/metrics/kpi` | Security KPI metrics |
| `GET` | `/api/v1/metrics/mttr` | Mean time to remediate |
| `GET` | `/api/v1/metrics/burndown` | Vulnerability burndown chart |
| `GET` | `/api/v1/metrics/executive-summary` | Executive security summary |
| `GET` | `/api/v1/attack-paths/overview` | Org-wide attack path analysis |
| `GET` | `/api/v1/attack-paths/graph/:productId` | Attack path graph for a product |
| `POST` | `/api/v1/agent/analyze/:productId` | AI agent deep product analysis |
| `POST` | `/api/v1/agent/chat` | Chat with AI security agent |
| `GET` | `/api/v1/sbom/overview` | Org-wide SBOM overview |
| `GET` | `/api/v1/sbom/product/:productId` | SBOM for a product |
| `POST` | `/api/v1/copilot/remediate/:findingId` | AI remediation for a finding |
| `POST` | `/api/v1/copilot/bulk-remediate` | Bulk AI remediation |
| `POST` | `/api/v1/llm-scanner/scan` | Scan code for AI/ML vulnerabilities |
| `GET` | `/api/v1/llm-scanner/overview` | LLM scanner overview |

---

## 🔌 CI/CD Integration

Import scan results directly from your pipeline:

```bash
# Import Trivy scan results
curl -X POST http://localhost:8000/api/v1/scans/import \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@trivy-results.json" \
  -F "scanner=Trivy" \
  -F "product_id=1"

# Import Semgrep results
curl -X POST http://localhost:8000/api/v1/scans/import \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@semgrep.json" \
  -F "scanner=Semgrep" \
  -F "product_id=1"
```

### GitHub Actions Example

```yaml
- name: Import scan results to Foxnode
  run: |
    curl -X POST ${{ secrets.FOXNODE_URL }}/api/v1/scans/import \
      -H "Authorization: Bearer ${{ secrets.FOXNODE_TOKEN }}" \
      -F "file=@trivy-results.json" \
      -F "scanner=Trivy" \
      -F "product_id=1"
```

---

## ⚙️ Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://foxnode:foxnode@localhost:5432/foxnode_aspm` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `SECRET_KEY` | JWT signing key | `change-me-in-production` |
| `CORS_ORIGINS` | Allowed CORS origins | `["http://localhost"]` |
| `JIRA_URL` | Jira instance URL | — |
| `JIRA_USERNAME` | Jira account email | — |
| `JIRA_API_TOKEN` | Jira API token | — |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL | — |

---

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`cd backend && pytest`)
5. Submit a pull request

See our [Contributing Guide](CONTRIBUTING.md) for more details.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⭐ Star History

If you find FoxNode ASPM useful, please consider giving it a star! It helps others discover the project.

---

<p align="center">
  Built with ❤️ by the <a href="https://github.com/valinorintelligence">Valinor Intelligence</a> team
</p>
