# Python Docker Demo (AI-Powered Security Monitor)

[![AI Powered](https://img.shields.io/badge/AI%20Powered-Heuristic%20Risk%20Engine-0A7B5C)](#why-call-it-ai-powered)

This started as a Flask + Docker learning project and evolved into a small AI-assisted security monitor for web traffic.

## What it does right now
- Logs requests, errors, and suspicious events into `logs/`
- Runs a background log tailer and emits alert records
- Blocks abusive IPs with exponential backoff
- Applies CORS, CSRF, payload-size, and query-validation checks
- Exposes live security status through APIs

## Why call it AI-powered?
This project uses an **AI-style signal fusion layer** (currently heuristic) instead of only binary allow/deny checks.

`GET /ai-insights` combines:
- alert severity mix (critical/high/medium/low)
- currently blocked IPs
- IPs with repeated violations

It returns a normalized risk score (`0-100`) and a risk band (`low|medium|high`) so operators can act quickly.

## API surface
- `GET /` simple response with detected client IP
- `GET /health` health probe
- `GET /csrf-token` sets/returns CSRF token
- `GET /alerts` returns recent in-memory alerts
- `GET /ai-insights` returns current AI-assisted risk summary

### Demo response (`GET /ai-insights`)
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

## Quick run
### Local
```bash
pip install -r requirements.txt
python app.py
```

### Docker
```bash
docker build -t python-docker-demo .
docker run -p 5000:5000 python-docker-demo
```

### Compose (dev)
```bash
docker compose up --build
```

### Compose (prod + nginx TLS)
1. Add certs:
- `certs/fullchain.pem`
- `certs/privkey.pem`
2. Start:
```bash
docker compose -f docker-compose.prod.yml up --build
```

## Practical notes from development
- The detection patterns are intentionally simple and easy to tune.
- False positives can happen; watch `logs/suspicious.log` before tightening rules.
- IP-based rate limits are useful, but they are not bot-proof behind shared proxies.
- The score in `/ai-insights` is interpretable on purpose; this is an ops tool, not a black box.

## Environment knobs
- `ALLOWED_CORS_ORIGINS`
- `CSRF_COOKIE_SECURE`
- `MAX_CONTENT_LENGTH_BYTES`
- `RATE_LIMIT_REQUESTS`
- `RATE_LIMIT_WINDOW_SECONDS`
- `RATE_LIMIT_BASE_BLOCK_SECONDS`
- `RATE_LIMIT_MAX_BLOCK_SECONDS`
- `MAX_QUERY_PARAMS`
- `MAX_QUERY_KEY_LENGTH`
- `MAX_QUERY_VALUE_LENGTH`

## Near-term roadmap
- Train a lightweight anomaly model from request/alert history
- Add per-endpoint baselines instead of global thresholds
- Forward alerts to Slack/Discord webhook
- Add regression tests for the rate-limiter and CSRF flow

## Files
```text
docker-new-app/
|- app.py
|- Dockerfile
|- docker-compose.yaml
|- docker-compose.prod.yml
|- nginx/nginx.conf
|- logs/                # created at runtime
|- requirements.txt
|- README.md
```
