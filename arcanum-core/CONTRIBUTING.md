# Contributing to Arcanum Core

Thank you for your interest in contributing to Arcanum Core! This document provides guidelines and information for contributors.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/arcanum-core.git`
3. Install dependencies: `pip install -e ".[dev]"`
4. Create a branch: `git checkout -b feature/your-feature`

## Development Setup

```bash
# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest --cov=arcanum -v

# Lint
ruff check arcanum/

# Build sandbox image
docker build -t arcanum-sandbox -f docker/Dockerfile .
```

## Project Structure

```
arcanum/
├── agent/     # AI agent engine, LLM client, skills, orchestrator
├── api/       # FastAPI backend + WebSocket
├── cli/       # Textual TUI interface
├── core/      # Config, database, CVE KB, stash, reports, alerts, i18n
├── sandbox/   # Docker container + browser automation
└── tools/     # 40-tool registry with wrappers
```

## Contribution Areas

### Adding New Tools
1. Add tool definition to `arcanum/tools/registry.json`
2. If the tool needs a Python wrapper, add it to the appropriate category in `arcanum/tools/`
3. Update the Dockerfile if new system packages are needed

### Adding Skills
1. Add a new `Skill` entry to `BUILTIN_SKILLS` in `arcanum/agent/skills.py`
2. Include descriptive keywords for auto-mapping
3. Define clear step-by-step instructions

### Adding Workflow Templates
1. Create a YAML file in `~/.arcanum/workflows/` or add to `BUILTIN_WORKFLOWS` in `arcanum/core/workflows.py`
2. Follow the existing template structure with steps, dependencies, and risk levels

### Adding Translations
1. Add a new language key to `arcanum/core/i18n.py`
2. Translate all strings in the `TRANSLATIONS` dict

## Code Style

- Python 3.11+ with type hints
- Line length: 100 characters (ruff)
- Use `async/await` for I/O operations
- Docstrings for public APIs

## Pull Request Process

1. Ensure tests pass: `pytest`
2. Ensure linting passes: `ruff check arcanum/`
3. Update documentation if needed
4. Write a clear PR description
5. Reference any related issues

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include reproduction steps for bugs
- Include system info: OS, Python version, Docker version, GPU/RAM

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
