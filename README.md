# RiskEngine: AI-Assisted Security Monitor

[![AI Powered](https://img.shields.io/badge/AI%20Powered-Heuristic%20Risk%20Engine-0A7B5C)](#project-description)

## Project Description
This project is a Flask-based web security monitor that runs locally or in Docker. It inspects incoming traffic, applies baseline protection checks, and produces an interpretable risk summary for operations teams.

Core capabilities:
- Request, error, and suspicious-event logging to `logs/`
- Alert generation from log activity
- IP blocking with exponential backoff for repeated abuse
- Security checks for CORS, CSRF, payload size, and query constraints
- API endpoints for live monitoring and AI-style risk insights

The AI-assisted layer is heuristic today: `GET /ai-insights` fuses multiple runtime signals into a `0-100` risk score and a risk level (`low`, `medium`, `high`).

## Quick Start Guide

### Option 1: Run locally
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Application URL: `http://localhost:5000`

### Option 2: Run with Docker
```bash
docker build -t riskengine .
docker run -p 5000:5000 riskengine
```

### Option 3: Run with Docker Compose (development)
```bash
docker compose up --build
```

### Option 4: Run production Compose (Nginx + TLS)
1. Add certificate files:
- `certs/fullchain.pem`
- `certs/privkey.pem`
2. Start services:
```bash
docker compose -f docker-compose.prod.yml up --build
```

### Key endpoints
- `GET /` application entry
- `GET /health` health check
- `GET /csrf-token` CSRF token retrieval
- `GET /alerts` recent in-memory alerts
- `GET /ai-insights` risk summary endpoint

## Screenshots / Demos
Use this section to showcase your running app and security insights. Suggested assets:
- Home/API response screenshot
- `/ai-insights` response screenshot
- Logs output (`logs/suspicious.log`) screenshot

If you add media files, place them in a `docs/images/` folder and reference them here:
```md
![Home endpoint](docs/images/home.png)
![AI insights endpoint](docs/images/ai-insights.png)
```

Example `GET /ai-insights` response:
```json
{
  "mode": "heuristic-ai-assist",
  "risk_score": 41,
  "risk_level": "medium",
  "signals": {
    "recent_alerts": 8,
    "severity_breakdown": {
      "critical": 0,
      "high": 3,
      "medium": 4,
      "low": 1
    },
    "currently_blocked_ips": 1,
    "ips_with_recent_violations": 2
  }
}
```

## Dependencies
Application/runtime dependencies:
- Python 3.10+ (recommended)
- Flask (from `requirements.txt`)
- Docker and Docker Compose (for containerized workflows)
- Nginx (used in production compose setup)

Install Python package dependencies:
```bash
pip install -r requirements.txt
```

## How to Contribute
1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make focused changes and test locally.
4. Commit with clear messages.
5. Push and open a Pull Request with:
- Problem statement
- What changed
- How it was tested
- Any screenshots (if UI/API output changed)

Contribution guidelines:
- Keep changes small and reviewable.
- Prefer explicit configuration over hard-coded values.
- Add or update tests when behavior changes.

## Support Information
For help or issues:
- Open a GitHub Issue with reproduction steps and logs.
- Include environment details (OS, Python version, Docker version).
- Include relevant endpoint output (for example, `/health` and `/ai-insights`) when reporting runtime problems.

Recommended issue template details:
- Expected behavior
- Actual behavior
- Steps to reproduce
- Error logs or stack trace

## Project Structure
```text
RiskEngine/
|- app.py
|- Dockerfile
|- docker-compose.yaml
|- docker-compose.prod.yml
|- nginx/nginx.conf
|- logs/                # created at runtime
|- requirements.txt
|- README.md
```
