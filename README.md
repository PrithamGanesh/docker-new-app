# Python Docker Demo

Flask-based security-aware web app with:
- request logging
- error logging
- suspicious behavior logging
- continuous log monitoring
- pattern-based alert generation

## 1. Architecture
```text
                   +------------------------+
                   |      Client/User       |
                   +-----------+------------+
                               |
                               v
                   +------------------------+
                   |      Flask App         |
                   |  (app.py, port 5000)   |
                   +-----------+------------+
                               |
         +---------------------+----------------------+
         |                     |                      |
         v                     v                      v
 +---------------+   +----------------+   +--------------------+
 | Request Hook  |   | Error Handler  |   | Monitor Thread     |
 | before_request|   | Exception Catch |   | continuous tailing |
 +-------+-------+   +--------+-------+   +---------+----------+
         |                    |                     |
         v                    v                     v
 +---------------+    +---------------+    +-------------------+
 | requests.log  |    |  errors.log   |    | pattern detection |
 +-------+-------+    +-------+-------+    +---------+---------+
         |                    |                     |
         +--------------------+----------+----------+
                                     |
                                     v
                            +-----------------+
                            | suspicious.log  |
                            +--------+--------+
                                     |
                                     v
                            +-----------------+
                            |  alerts.log     |
                            | + /alerts API   |
                            +-----------------+
```

## 2. Tech Stack
- Language: Python 3.9
- Framework: Flask
- Containerization: Docker, Docker Compose
- Logging: Python built-in `logging`
- Pattern Matching: Python `re` module
- Concurrency: Python `threading` (daemon monitor thread)

## 3. Project Structure
```text
docker-new-app/
├─ app.py
├─ requirements.txt
├─ Dockerfile
├─ docker-compose.yaml
├─ README.md
├─ logs/                    # created at runtime
│  ├─ requests.log
│  ├─ errors.log
│  ├─ suspicious.log
│  └─ alerts.log
├─ templates/
└─ static/
```

## 4. Features
### Request Logging
- Every incoming HTTP request is logged to `logs/requests.log`.
- Captured fields: method, path, IP, user agent.

### Error Logging
- Unhandled exceptions are captured globally and logged with traceback in `logs/errors.log`.
- API response on unhandled error: HTTP `500` with `{"error":"internal server error"}`.

### Suspicious Behavior Logging
- Request payload and path are checked for suspicious signatures.
- High request rate per IP is tracked in a sliding window.
- Events are written to `logs/suspicious.log`.

### Continuous Monitoring and Alerts
- A background daemon continuously reads new lines from:
  - `logs/requests.log`
  - `logs/errors.log`
  - `logs/suspicious.log`
- Pattern matches trigger generated alerts in `logs/alerts.log`.
- Recent alerts are also stored in memory and returned by `GET /alerts`.

## 5. API Endpoints
### `GET /`
- Returns: greeting and visitor IP info.

### `GET /health`
- Returns: `{"status":"ok"}` with HTTP `200`.

### `GET /alerts`
- Returns recent generated alerts.
- Example response:
```json
{
  "count": 2,
  "alerts": [
    {
      "timestamp": "2026-02-18 20:10:00",
      "source_file": "suspicious.log",
      "severity": "high",
      "pattern": "signature_match",
      "line": "Pattern match | ip=127.0.0.1 | method=GET | ..."
    }
  ]
}
```

## 6. How to Execute
### Option A: Run with Docker
1. Build image:
```bash
docker build -t python-docker-demo .
```
2. Run container:
```bash
docker run -p 5000:5000 python-docker-demo
```
3. Open:
- `http://localhost:5000/`
- `http://localhost:5000/health`
- `http://localhost:5000/alerts`

### Option B: Run with Docker Compose
1. Start:
```bash
docker compose up --build
```
2. Open:
- `http://localhost:5000/`
- `http://localhost:5000/health`
- `http://localhost:5000/alerts`

### Option C: Run Locally (without Docker)
1. Create and activate virtual environment (optional but recommended).
2. Install dependencies:
```bash
pip install -r requirements.txt
```
3. Start app:
```bash
python app.py
```
4. Open:
- `http://127.0.0.1:5000/`

## 7. Logging and Alert Rules
### Suspicious Request Patterns
- Path traversal: `../`
- SQL-like injection fragments: `union select`, `or 1=1`, `drop table`
- Script injection fragment: `<script`
- Sensitive probing strings: `/etc/passwd`, `cmd.exe`, `powershell`

### Traffic Spike Rule
- If a single IP exceeds `120` requests in `60` seconds, a suspicious event is logged.

### Alert Pattern Sources
- Unhandled exceptions from `errors.log`
- Suspicious signature matches from `suspicious.log`
- High request-rate markers from `suspicious.log`
- Attack-keyword matches from monitored lines

## 8. Observability Quick Commands
### Linux/macOS
```bash
tail -f logs/requests.log
tail -f logs/errors.log
tail -f logs/suspicious.log
tail -f logs/alerts.log
```

### Windows PowerShell
```powershell
Get-Content .\logs\requests.log -Wait
Get-Content .\logs\errors.log -Wait
Get-Content .\logs\suspicious.log -Wait
Get-Content .\logs\alerts.log -Wait
```

## 9. FAQ
### Why is `/alerts` empty?
- Alerts are only created when monitored log lines match alert patterns.
- Generate some traffic or suspicious input first.

### Why are there no files under `logs/` yet?
- Log files are created at runtime when requests or events occur.

### Can this replace a full SIEM or IDS?
- No. This project provides a lightweight in-app detection/alert layer, not a full security platform.

### Does this block malicious requests?
- No. It currently logs and alerts. Blocking can be added later via middleware/firewall/rate-limiter.

### Is alert state persistent?
- `alerts.log` is persistent on disk.
- `/alerts` in-memory list resets when the process restarts.

## 10. Troubleshooting
### Port 5000 already in use
- Change mapping in docker run/compose or free the port.

### Container starts but app is inaccessible
- Confirm container is running and port mapping is correct (`5000:5000`).

### No suspicious alerts seen
- Use a test query such as:
```bash
curl "http://localhost:5000/?q=union%20select"
```

## 11. Future Enhancements
- Alert deduplication and cooldown windows
- Log rotation and retention policy
- Email/Slack/Webhook integrations for alerts
- Metrics endpoint and dashboard integration
