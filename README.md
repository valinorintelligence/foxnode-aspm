# Foxnode ASPM

**Open-source Application Security Posture Management Platform**

Foxnode ASPM is a modern, developer-friendly platform for managing application security vulnerabilities across your entire software portfolio. It aggregates findings from 20+ security scanners, deduplicates them intelligently, and provides actionable dashboards to track your security posture.

## Key Features

- **Modern Dark UI** — Built with React + Tailwind CSS for a fast, beautiful experience
- **Multi-Scanner Support** — Import results from Trivy, Semgrep, Snyk, OWASP ZAP, Nuclei, Gitleaks, Bandit, and more
- **Smart Deduplication** — Hash-based deduplication prevents duplicate findings across scans
- **Product Management** — Organize findings by products, engagements, and tests
- **Real-time Dashboard** — Severity distribution, scanner breakdown, risk trends, and top vulnerable products
- **24+ Tool Integrations** — SAST, DAST, SCA, container, cloud, IaC, and secret detection tools
- **REST API** — Full API for CI/CD pipeline integration
- **Role-Based Access** — Admin, Manager, Analyst, and Viewer roles
- **Docker-Ready** — Single command deployment with Docker Compose

## Quick Start

### Using Docker Compose (Recommended)

```bash
git clone https://github.com/your-username/foxnode-aspm.git
cd foxnode-aspm
cp .env.example .env
docker compose up -d
```

The app will be available at:
- **Frontend**: http://localhost
- **API**: http://localhost:8000/docs
- **API Health**: http://localhost:8000/api/health

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

## Supported Scanners

| Category | Tools |
|----------|-------|
| **SAST** | Semgrep, SonarQube, Bandit, ESLint Security |
| **DAST** | OWASP ZAP, Nuclei, Burp Suite |
| **SCA** | Trivy, Snyk, Dependency-Check |
| **Container** | Trivy |
| **Cloud** | AWS Security Hub, Prowler, ScoutSuite |
| **IaC** | Checkov, tfsec |
| **Secrets** | Gitleaks, TruffleHog |
| **Generic** | CSV/JSON import for any tool |

## Architecture

```
foxnode-aspm/
├── backend/              # FastAPI + SQLAlchemy async
│   ├── app/
│   │   ├── api/          # REST endpoints
│   │   ├── core/         # Config, DB, security
│   │   ├── models/       # SQLAlchemy models
│   │   ├── parsers/      # Scanner result parsers
│   │   ├── schemas/      # Pydantic schemas
│   │   └── services/     # Business logic
│   └── requirements.txt
├── frontend/             # React + TypeScript + Tailwind
│   ├── src/
│   │   ├── components/   # Reusable UI components
│   │   ├── pages/        # Route pages
│   │   ├── services/     # API client
│   │   └── store/        # Zustand state management
│   └── package.json
├── docker/               # Dockerfiles and nginx config
├── docker-compose.yml    # Full stack deployment
└── .env.example          # Configuration template
```

## API Documentation

Once running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Create account |
| POST | `/api/v1/auth/login` | Get access token |
| GET | `/api/v1/dashboard/stats` | Dashboard metrics |
| GET/POST | `/api/v1/products` | Manage products |
| GET/POST | `/api/v1/findings` | Manage findings |
| POST | `/api/v1/scans/import` | Import scan results |
| GET | `/api/v1/integrations/supported-tools` | List available tools |

## CI/CD Integration

Import scan results directly from your pipeline:

```bash
curl -X POST http://localhost:8000/api/v1/scans/import \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@trivy-results.json" \
  -F "scanner=Trivy" \
  -F "product_id=1"
```

## Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.
