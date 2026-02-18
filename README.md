# Python Docker Demo

Security-aware Flask app with:
- request/error/suspicious logging
- continuous log monitoring
- pattern-based alerting
- CORS and CSRF protections
- active rate limiting with temporary blocking
- input size and query validation

## 1. Architecture Diagram
```text
                 +----------------------+
                 |      Client/API      |
                 +----------+-----------+
                            |
                            v
                 +----------------------+
                 |      Nginx TLS       |
                 |  (prod: 443/HTTPS)   |
                 +----------+-----------+
                            |
                            v
                 +----------------------+
                 |      Flask App       |
                 |       app.py         |
                 +----------+-----------+
                            |
      +---------------------+---------------------+
      |                     |                     |
      v                     v                     v
+-------------+     +---------------+     +------------------+
| before_req  |     | error handlers|     | monitor thread   |
| - CORS/CSRF |     | - HTTP/500    |     | reads log lines  |
| - size/args |     +-------+-------+     +--------+---------+
| - rate limit|             |                      |
+------+------+             v                      v
       |            +---------------+      +------------------+
       +----------->| logs/*.log     |----->| alert patterns   |
                    | req/err/susp   |      | + alerts.log     |
                    +---------------+      +------------------+
```

## 2. Tech Stack
- Python 3.9
- Flask
- Docker + Docker Compose
- Nginx (production TLS reverse proxy)
- Python `logging`, `threading`, `re`, `secrets`

## 3. Key Security Controls
### CORS
- Only whitelisted origins are allowed via `ALLOWED_CORS_ORIGINS`.
- Dynamic `Access-Control-Allow-Origin` only for approved origins.

### CSRF
- Double-submit CSRF token pattern.
- Token stored in `csrf_token` cookie and must match `X-CSRF-Token` header for `POST/PUT/PATCH/DELETE`.
- Token endpoint: `GET /csrf-token`.

### Rate Limiting and Blocking
- Per-IP sliding window limiter.
- Defaults:
  - `30` requests / `60` seconds
  - temporary block starts at `30s`
  - exponential backoff up to `300s`
- Blocked requests return `429` with `Retry-After`.

### Input Validation
- Max request body size via Flask `MAX_CONTENT_LENGTH` (default `1MB`).
- Query parameter validation:
  - max params: `20`
  - key length: `64`
  - value length: `512`
  - allowed key charset: `[A-Za-z0-9_.-]`

### Security Headers
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: same-origin`
- HSTS at Nginx in production TLS config.

## 4. Logging and Alerts
Runtime logs are created under `logs/`:
- `requests.log`
- `errors.log`
- `suspicious.log`
- `alerts.log`

Background monitoring continuously tails request/error/suspicious logs, detects patterns, and generates alerts.

## 5. API Endpoints
- `GET /` health-style demo response
- `GET /health` returns `{"status":"ok"}`
- `GET /alerts` returns in-memory recent alerts
- `GET /csrf-token` returns/sets CSRF token

## 6. How to Execute
### Option A: Local Python
1. Install dependencies:
```bash
pip install -r requirements.txt
```
2. Run:
```bash
python app.py
```
3. Open:
- `http://127.0.0.1:5000/`

### Option B: Docker
1. Build:
```bash
docker build -t python-docker-demo .
```
2. Run:
```bash
docker run -p 5000:5000 python-docker-demo
```

### Option C: Docker Compose (dev)
```bash
docker compose up --build
```

### Option D: Docker Compose (prod with TLS via Nginx)
1. Place cert files:
- `certs/fullchain.pem`
- `certs/privkey.pem`
2. Start:
```bash
docker compose -f docker-compose.prod.yml up --build
```
3. Open:
- `https://localhost/`

## 7. Environment Variables
- `ALLOWED_CORS_ORIGINS` (comma-separated origins)
- `CSRF_COOKIE_SECURE` (`1` in HTTPS production)
- `MAX_CONTENT_LENGTH_BYTES` (default `1048576`)
- `RATE_LIMIT_REQUESTS` (default `30`)
- `RATE_LIMIT_WINDOW_SECONDS` (default `60`)
- `RATE_LIMIT_BASE_BLOCK_SECONDS` (default `30`)
- `RATE_LIMIT_MAX_BLOCK_SECONDS` (default `300`)
- `MAX_QUERY_PARAMS` (default `20`)
- `MAX_QUERY_KEY_LENGTH` (default `64`)
- `MAX_QUERY_VALUE_LENGTH` (default `512`)

## 8. FAQs
### Why am I getting `403 CSRF token missing or invalid`?
- For unsafe methods, include cookie `csrf_token` and matching `X-CSRF-Token` header.
- Fetch token first from `GET /csrf-token`.

### Why am I getting `429 rate limit exceeded`?
- Your IP exceeded the configured request threshold.
- Respect `Retry-After` and reduce request rate.

### Why can browser calls fail due to CORS?
- Origin is not in `ALLOWED_CORS_ORIGINS`.
- Add the exact origin (scheme + host + port) to the env var.

### Why is `/alerts` empty?
- Alerts appear only after matching suspicious/error patterns.

## 9. Troubleshooting
### Large upload rejected
- Expected if body is over `MAX_CONTENT_LENGTH_BYTES`.
- Increase env var only if needed.

### HTTPS compose fails to start Nginx
- Check cert files exist at:
  - `certs/fullchain.pem`
  - `certs/privkey.pem`

### App reachable directly on 5000 but not through HTTPS
- Verify Nginx container is running and ports `80/443` are mapped.

## 10. Project Structure
```text
docker-new-app/
|- app.py
|- Dockerfile
|- docker-compose.yaml
|- docker-compose.prod.yml
|- nginx/
|  |- nginx.conf
|- certs/                  # provide TLS certs here
|- logs/                   # runtime-created log files
|- requirements.txt
|- README.md
```
