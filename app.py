import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, make_response, request
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH_BYTES", 1_048_576))

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Fast signatures for suspicious traffic. Tune over time.
SUSPICIOUS_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"(?i)(union\s+select|select\s+\*|drop\s+table|or\s+1=1)"),
    re.compile(r"(?i)<script\b"),
    re.compile(r"(?i)(/etc/passwd|cmd\.exe|powershell)"),
]

REQUEST_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", 60))
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", 30))
RATE_LIMIT_BASE_BLOCK_SECONDS = int(os.getenv("RATE_LIMIT_BASE_BLOCK_SECONDS", 30))
RATE_LIMIT_MAX_BLOCK_SECONDS = int(os.getenv("RATE_LIMIT_MAX_BLOCK_SECONDS", 300))
MAX_QUERY_PARAMS = int(os.getenv("MAX_QUERY_PARAMS", 20))
MAX_QUERY_KEY_LENGTH = int(os.getenv("MAX_QUERY_KEY_LENGTH", 64))
MAX_QUERY_VALUE_LENGTH = int(os.getenv("MAX_QUERY_VALUE_LENGTH", 512))
ALLOWED_QUERY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
ALLOWED_CORS_ORIGINS = {
    origin.strip()
    for origin in os.getenv(
        "ALLOWED_CORS_ORIGINS", "http://localhost:5000,http://127.0.0.1:5000"
    ).split(",")
    if origin.strip()
}
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

ip_buckets = defaultdict(
    lambda: {
        "times": deque(),
        "blocked_until": 0.0,
        "violations": 0,
    }
)
MAX_ALERTS_IN_MEMORY = 200
MONITORED_LOG_FILES = ("requests.log", "errors.log", "suspicious.log")
hot_alert_buffer = deque(maxlen=MAX_ALERTS_IN_MEMORY)
log_tail_guard = threading.Lock()
is_tailer_live = False

alert_rules = [
    ("critical", "unhandled_exception", re.compile(r"Unhandled error", re.IGNORECASE)),
    ("high", "signature_match", re.compile(r"Pattern match", re.IGNORECASE)),
    ("medium", "traffic_spike", re.compile(r"(High request rate|rate limiter)", re.IGNORECASE)),
    ("high", "attack_keywords", re.compile(r"union\s+select|<script|\.{2}/|/etc/passwd|cmd\.exe", re.IGNORECASE)),
]


def setup_logger(name: str, filename: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(os.path.join(LOG_DIR, filename))
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


request_logger = setup_logger("request_logger", "requests.log", logging.INFO)
error_logger = setup_logger("error_logger", "errors.log", logging.ERROR)
suspicious_logger = setup_logger("suspicious_logger", "suspicious.log", logging.WARNING)
alert_logger = setup_logger("alert_logger", "alerts.log", logging.WARNING)


def create_alert(source_file: str, severity: str, pattern_name: str, line: str) -> None:
    alert = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source_file": source_file,
        "severity": severity,
        "pattern": pattern_name,
        "line": line.strip(),
    }
    hot_alert_buffer.append(alert)
    alert_logger.warning(
        "severity=%s | pattern=%s | source=%s | line=%s",
        severity,
        pattern_name,
        source_file,
        line.strip(),
    )


def detect_patterns(source_file: str, line: str) -> None:
    for severity, name, pattern in alert_rules:
        if pattern.search(line):
            create_alert(source_file, severity, name, line)


def monitor_logs_forever(poll_interval: float = 1.0) -> None:
    file_offsets = {}
    while True:
        for log_filename in MONITORED_LOG_FILES:
            path = os.path.join(LOG_DIR, log_filename)
            if not os.path.exists(path):
                continue

            if log_filename not in file_offsets:
                file_offsets[log_filename] = os.path.getsize(path)

            current_size = os.path.getsize(path)
            if current_size < file_offsets[log_filename]:
                file_offsets[log_filename] = 0

            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(file_offsets[log_filename])
                for line in f:
                    detect_patterns(log_filename, line)
                file_offsets[log_filename] = f.tell()

        time.sleep(poll_interval)


def start_log_monitoring() -> None:
    global is_tailer_live
    with log_tail_guard:
        if is_tailer_live:
            return
        thread = threading.Thread(target=monitor_logs_forever, daemon=True)
        thread.start()
        is_tailer_live = True


def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def validate_query_params() -> tuple[bool, str]:
    if len(request.args) > MAX_QUERY_PARAMS:
        return False, f"Too many query parameters; max={MAX_QUERY_PARAMS}"

    for key, values in request.args.lists():
        if len(key) > MAX_QUERY_KEY_LENGTH:
            return (
                False,
                f"Query key too long for '{key[:20]}'; max={MAX_QUERY_KEY_LENGTH}",
            )
        if not ALLOWED_QUERY_KEY_PATTERN.match(key):
            return False, f"Invalid query key '{key}'"
        for value in values:
            if len(value) > MAX_QUERY_VALUE_LENGTH:
                return (
                    False,
                    f"Query value too long for key '{key}'; max={MAX_QUERY_VALUE_LENGTH}",
                )
    return True, ""


def enforce_rate_limit(ip: str) -> tuple[bool, int]:
    state = ip_buckets[ip]
    now = time.time()

    if now < state["blocked_until"]:
        retry_after = int(state["blocked_until"] - now) + 1
        return False, retry_after

    times = state["times"]
    times.append(now)
    while times and (now - times[0]) > REQUEST_WINDOW_SECONDS:
        times.popleft()

    if len(times) > RATE_LIMIT_REQUESTS:
        state["violations"] += 1
        block_seconds = min(
            RATE_LIMIT_BASE_BLOCK_SECONDS * (2 ** (state["violations"] - 1)),
            RATE_LIMIT_MAX_BLOCK_SECONDS,
        )
        state["blocked_until"] = now + block_seconds
        state["times"].clear()
        return False, int(block_seconds)

    return True, 0


def validate_csrf(ip: str) -> tuple[bool, str]:
    if request.method not in UNSAFE_METHODS:
        return True, ""

    cookie_token = request.cookies.get("csrf_token", "")
    header_token = request.headers.get("X-CSRF-Token", "")

    if not cookie_token or not header_token or cookie_token != header_token:
        suspicious_logger.warning(
            "CSRF validation failed | ip=%s | method=%s | path=%s",
            ip,
            request.method,
            request.path,
        )
        return False, "CSRF token missing or invalid"

    return True, ""


def request_payload_for_detection() -> str:
    body_text = ""
    if request.method in UNSAFE_METHODS:
        body_text = request.get_data(cache=True, as_text=True) or ""

    return " ".join(
        [
            request.path or "",
            request.query_string.decode("utf-8", errors="ignore"),
            body_text,
        ]
    )


@app.before_request
def security_and_logging_hooks():
    start_log_monitoring()
    ip = client_ip()
    ua = request.headers.get("User-Agent", "-")
    request_logger.info("%s %s | ip=%s | ua=%s", request.method, request.path, ip, ua)

    content_length = request.content_length
    if content_length and content_length > app.config["MAX_CONTENT_LENGTH"]:
        suspicious_logger.warning(
            "Request body too large | ip=%s | method=%s | path=%s | bytes=%d",
            ip,
            request.method,
            request.path,
            content_length,
        )
        return {"error": "request body too large"}, 413

    valid_query, reason = validate_query_params()
    if not valid_query:
        suspicious_logger.warning(
            "Query validation failed | ip=%s | method=%s | path=%s | reason=%s",
            ip,
            request.method,
            request.path,
            reason,
        )
        return {"error": "invalid query parameters", "reason": reason}, 400

    allowed_request, retry_after = enforce_rate_limit(ip)
    if not allowed_request:
        suspicious_logger.warning(
            "Request blocked by rate limiter | ip=%s | method=%s | path=%s | retry_after=%ds",
            ip,
            request.method,
            request.path,
            retry_after,
        )
        response = make_response(
            jsonify(
                {
                    "error": "rate limit exceeded",
                    "retry_after_seconds": retry_after,
                }
            ),
            429,
        )
        response.headers["Retry-After"] = str(retry_after)
        return response

    valid_csrf, csrf_reason = validate_csrf(ip)
    if not valid_csrf:
        return {"error": csrf_reason}, 403

    full_payload = request_payload_for_detection()

    matched = [
        pattern.pattern for pattern in SUSPICIOUS_PATTERNS if pattern.search(full_payload)
    ]
    if matched:
        suspicious_logger.warning(
            "Pattern match | ip=%s | method=%s | path=%s | patterns=%s",
            ip,
            request.method,
            request.full_path,
            ",".join(matched),
        )


@app.after_request
def add_security_headers(response):
    origin = request.headers.get("Origin", "")
    if origin and origin in ALLOWED_CORS_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type,X-CSRF-Token"

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"

    if not request.cookies.get("csrf_token"):
        response.set_cookie(
            "csrf_token",
            secrets.token_urlsafe(32),
            httponly=False,
            secure=bool(os.getenv("CSRF_COOKIE_SECURE", "0") == "1"),
            samesite="Lax",
            max_age=86400,
        )
    return response


@app.route("/csrf-token", methods=["GET"])
def csrf_token():
    token = request.cookies.get("csrf_token") or secrets.token_urlsafe(32)
    response = jsonify({"csrf_token": token})
    response.set_cookie(
        "csrf_token",
        token,
        httponly=False,
        secure=bool(os.getenv("CSRF_COOKIE_SECURE", "0") == "1"),
        samesite="Lax",
        max_age=86400,
    )
    return response


@app.route("/alerts", methods=["GET", "OPTIONS"])
@app.route("/health", methods=["GET", "OPTIONS"])
@app.route("/", methods=["GET", "OPTIONS"])
def options_support():
    if request.method == "OPTIONS":
        return "", 204
    if request.path == "/":
        visitor_ip = client_ip()
        return f"Hello! Your IP {visitor_ip} has been logged."
    if request.path == "/health":
        return {"status": "ok"}, 200
    return {"count": len(hot_alert_buffer), "alerts": list(hot_alert_buffer)}, 200


@app.route("/ai-insights", methods=["GET"])
def ai_insights():
    # Quick heuristic score, meant for operators and demos.
    sev_weights = {"critical": 10, "high": 6, "medium": 3, "low": 1}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    weighted_alert_score = 0

    for alert in hot_alert_buffer:
        sev = alert.get("severity", "low")
        if sev not in severity_counts:
            severity_counts["low"] += 1
            weighted_alert_score += sev_weights["low"]
            continue
        severity_counts[sev] += 1
        weighted_alert_score += sev_weights[sev]

    blocked_ips = 0
    bursty_ips = 0
    now = time.time()
    for state in ip_buckets.values():
        if now < state["blocked_until"]:
            blocked_ips += 1
        if state["violations"] > 0:
            bursty_ips += 1

    risk_score = min(100, weighted_alert_score + blocked_ips * 12 + bursty_ips * 4)
    if risk_score >= 70:
        risk_level = "high"
    elif risk_score >= 35:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "mode": "heuristic-ai-assist",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "signals": {
            "recent_alerts": len(hot_alert_buffer),
            "severity_breakdown": severity_counts,
            "currently_blocked_ips": blocked_ips,
            "ips_with_recent_violations": bursty_ips,
        },
    }, 200


@app.errorhandler(RequestEntityTooLarge)
def handle_entity_too_large(error):
    suspicious_logger.warning(
        "Request rejected by MAX_CONTENT_LENGTH | ip=%s | path=%s",
        client_ip(),
        request.path,
    )
    return {"error": "request body too large"}, 413


@app.errorhandler(HTTPException)
def handle_http_exception(error):
    return {"error": error.name, "message": error.description}, error.code


@app.errorhandler(Exception)
def log_unhandled_error(error):
    error_logger.exception(
        "Unhandled error | method=%s | path=%s | ip=%s | error=%s",
        request.method,
        request.path,
        client_ip(),
        str(error),
    )
    return {"error": "internal server error"}, 500


if __name__ == "__main__":
    start_log_monitoring()
    app.run(host="0.0.0.0", port=5000)
