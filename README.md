<p align="center">
  <img src="docs/images/architecture-flowchart.svg" alt="Foxnode ASPM Architecture" width="100%"/>
</p>

<h1 align="center">Foxnode ASPM</h1>
<p align="center"><strong>Open-source Application Security Posture Management Platform</strong></p>
<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#dashboard-preview">Dashboard</a> •
  <a href="#supported-scanners">Scanners</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#api-documentation">API Docs</a> •
  <a href="#contributing">Contributing</a>
</p>

---

Foxnode ASPM is a modern, developer-friendly platform for managing application security vulnerabilities across your entire software portfolio. It aggregates findings from **16+ security scanners**, deduplicates them intelligently, and provides actionable dashboards to track your security posture.

> 🔥 Built from the ground up with React 18, TailwindCSS dark theme, FastAPI async backend, and first-class integrations with Jira and Slack.

---

## Dashboard Preview

<p align="center">
  <img src="docs/images/dashboard-mockup.svg" alt="Foxnode ASPM Dashboard" width="100%"/>
</p>

---

## Features

| Category | What You Get |
|----------|-------------|
| 🎨 **Modern Dark UI** | React 18 + TailwindCSS — fast, beautiful, responsive |
| 🔍 **16 Scanner Parsers** | Semgrep, Trivy, Snyk, ZAP, Nuclei, Gitleaks, Bandit, Checkov, SonarQube, Prowler, tfsec, TruffleHog, Dependency-Check, SARIF, and more |
| 🧠 **Smart Deduplication** | Hash-based dedup prevents duplicate findings across scans |
| 📊 **Real-time Dashboard** | Severity distribution, scanner breakdown, risk trends, top vulnerable products |
| 📦 **Product Management** | Organize findings by products, engagements, and test campaigns |
| 🔗 **Jira Integration** | Create issues from findings with auto-mapped severity → priority, label tagging, and bidirectional status sync |
| 🔔 **Slack Notifications** | Alerts for new findings and scan completions, configurable severity thresholds |
| 🛡️ **RBAC** | Admin, Manager, Analyst, and Viewer roles with granular permissions |
| 🐳 **Docker-Ready** | One-command deployment with Docker Compose |
| ⚡ **REST API** | Full API for CI/CD pipeline integration |
| 🔄 **GitHub Actions CI/CD** | Built-in pipelines for lint, test, build, security scan, and Docker publish |

---

## Data Flow & RBAC

<p align="center">
  <img src="docs/images/data-flow.svg" alt="Foxnode ASPM Data Flow" width="100%"/>
</p>

---

## Quick Start

### Using Docker Compose (Recommended)

```bash
git clone https://github.com/valinorintelligence/foxnode-aspm.git
cd foxnode-aspm
cp .env.example .env
docker compose up -d
```

The app will be available at:
- **Frontend**: http://localhost
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/api/health

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

## Supported Scanners

| Category | Tools | Parser |
|----------|-------|--------|
| **SAST** | Semgrep, SonarQube, Bandit | `semgrep`, `sonarqube`, `bandit` |
| **DAST** | OWASP ZAP, Nuclei | `zap`, `nuclei` |
| **SCA** | Trivy, Snyk, OWASP Dependency-Check | `trivy`, `snyk`, `dependency_check` |
| **Cloud Security** | Prowler | `prowler` |
| **IaC** | Checkov, tfsec | `checkov`, `tfsec` |
| **Secrets** | Gitleaks, TruffleHog | `gitleaks`, `trufflehog` |
| **Universal** | SARIF format (GitHub CodeQL, etc.) | `sarif` |
| **Generic** | Any tool via JSON/CSV | `generic` |

---

## Architecture

```
foxnode-aspm/
├── backend/                  # FastAPI + SQLAlchemy async
│   ├── app/
│   │   ├── api/              # REST endpoints (auth, products, findings, scans, jira, notifications, users)
│   │   ├── core/             # Config, DB, security, RBAC
│   │   ├── models/           # SQLAlchemy models (User, Product, Finding, Integration, ScanImport)
│   │   ├── parsers/          # 16 scanner result parsers + registry
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   └── services/         # Jira service, Notification service
│   └── requirements.txt
├── frontend/                 # React 18 + TypeScript + Vite + TailwindCSS
│   ├── src/
│   │   ├── components/       # Layout (Sidebar, Header), SeverityBadge
│   │   ├── pages/            # Dashboard, Products, Findings, Engagements, Integrations, ScanImport, Settings
│   │   ├── services/         # Axios API client (auth, products, findings, scans, jira, notifications, users)
│   │   └── store/            # Zustand auth state management
│   └── package.json
├── docker/                   # Dockerfiles + nginx config
├── .github/workflows/        # CI/CD pipeline + release workflow
├── docker-compose.yml        # Full stack deployment
└── .env.example              # Configuration template
```

---

## API Documentation

Once running, visit:
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

---

## CI/CD Integration

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

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://foxnode:foxnode@localhost:5432/foxnode_aspm` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `SECRET_KEY` | JWT signing key | `change-me-in-production` |
| `JIRA_URL` | Jira instance URL | — |
| `JIRA_USERNAME` | Jira account email | — |
| `JIRA_API_TOKEN` | Jira API token | — |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL | — |

---

## Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`cd backend && pytest`)
5. Submit a pull request

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Built with ❤️ by the <a href="https://github.com/valinorintelligence">Valinor Intelligence</a> team
</p>
