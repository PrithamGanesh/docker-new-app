import html
import logging
import os
import re
import secrets
import threading
import time
import unicodedata
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote_plus

from flask import Flask, current_app, jsonify, make_response, request
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

DEFAULT_MAX_CONTENT_LENGTH_BYTES = 1_048_576
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60
DEFAULT_RATE_LIMIT_REQUESTS = 30
DEFAULT_RATE_LIMIT_BASE_BLOCK_SECONDS = 30
DEFAULT_RATE_LIMIT_MAX_BLOCK_SECONDS = 300
DEFAULT_MAX_QUERY_PARAMS = 20
DEFAULT_MAX_QUERY_KEY_LENGTH = 64
DEFAULT_MAX_QUERY_VALUE_LENGTH = 512
DEFAULT_MAX_ALERTS_IN_MEMORY = 200
DEFAULT_LOG_MONITOR_POLL_INTERVAL_SECONDS = 1.0
DEFAULT_CSRF_COOKIE_MAX_AGE_SECONDS = 86_400

LOG_DIR = "logs"
MONITORED_LOG_FILES = ("requests.log", "errors.log", "suspicious.log")
ALLOWED_QUERY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Expanded detection signatures. Matching happens on normalized/decoded payloads.
SUSPICIOUS_SIGNATURES = [
    ("path_traversal", r"(?:\.\./|\.\.\\|/etc/passwd|\\windows\\win\.ini|boot\.ini)"),
    (
        "sqli",
        r"(?:union\s+select|select\s+\*|drop\s+table|or\s+1=1|information_schema|benchmark\s*\(|sleep\s*\()",
    ),
    (
        "xss",
        r"(?:<script\b|javascript:|onerror\s*=|onload\s*=|document\.cookie|<img\b[^>]*on\w+\s*=)",
    ),
    ("command_injection", r"(?:cmd\.exe|powershell(?:\.exe)?|/bin/(?:sh|bash)|;\s*(?:cat|ls|curl|wget)\b)"),
    ("template_injection", r"(?:\{\{.*\}\}|\$\{.*\}|<%=.*%>)"),
    ("prototype_pollution", r"(?:__proto__|constructor\.prototype)"),
    ("sensitive_file_access", r"(?:/proc/self/environ|id_rsa|\.env\b|web\.config)"),
    ("ssrf_hint", r"(?:169\.254\.169\.254|metadata\.google\.internal|localhost(?::\d+)?)"),
]

LOG_ALERT_RULES = [
    ("critical", "unhandled_exception", re.compile(r"Unhandled error", re.IGNORECASE)),
    ("high", "signature_match", re.compile(r"Pattern match", re.IGNORECASE)),
    ("medium", "traffic_spike", re.compile(r"(High request rate|rate limiter)", re.IGNORECASE)),
    (
        "high",
        "attack_keywords",
        re.compile(r"union\s+select|<script|\.{2}/|/etc/passwd|cmd\.exe", re.IGNORECASE),
    ),
]


@dataclass(frozen=True)
class SecurityConfig:
    max_content_length_bytes: int
    rate_limit_window_seconds: int
    rate_limit_requests: int
    rate_limit_base_block_seconds: int
    rate_limit_max_block_seconds: int
    max_query_params: int
    max_query_key_length: int
    max_query_value_length: int
    max_alerts_in_memory: int
    log_monitor_poll_interval_seconds: float
    csrf_cookie_secure: bool
    csrf_cookie_max_age_seconds: int
    allowed_cors_origins: set[str]

    @staticmethod
    def _safe_int(env_key: str, default: int, minimum: int = 1) -> int:
        try:
            return max(minimum, int(os.getenv(env_key, default)))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _safe_float(env_key: str, default: float, minimum: float = 0.1) -> float:
        try:
            return max(minimum, float(os.getenv(env_key, default)))
        except (TypeError, ValueError):
            return default

    @classmethod
    def from_env(cls) -> "SecurityConfig":
        allowed_origins = {
            origin.strip()
            for origin in os.getenv(
                "ALLOWED_CORS_ORIGINS",
                "http://localhost:5000,http://127.0.0.1:5000",
            ).split(",")
            if origin.strip()
        }

        return cls(
            max_content_length_bytes=cls._safe_int(
                "MAX_CONTENT_LENGTH_BYTES",
                DEFAULT_MAX_CONTENT_LENGTH_BYTES,
                minimum=1,
            ),
            rate_limit_window_seconds=cls._safe_int(
                "RATE_LIMIT_WINDOW_SECONDS",
                DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
                minimum=1,
            ),
            rate_limit_requests=cls._safe_int(
                "RATE_LIMIT_REQUESTS",
                DEFAULT_RATE_LIMIT_REQUESTS,
                minimum=1,
            ),
            rate_limit_base_block_seconds=cls._safe_int(
                "RATE_LIMIT_BASE_BLOCK_SECONDS",
                DEFAULT_RATE_LIMIT_BASE_BLOCK_SECONDS,
                minimum=1,
            ),
            rate_limit_max_block_seconds=cls._safe_int(
                "RATE_LIMIT_MAX_BLOCK_SECONDS",
                DEFAULT_RATE_LIMIT_MAX_BLOCK_SECONDS,
                minimum=1,
            ),
            max_query_params=cls._safe_int("MAX_QUERY_PARAMS", DEFAULT_MAX_QUERY_PARAMS, minimum=1),
            max_query_key_length=cls._safe_int(
                "MAX_QUERY_KEY_LENGTH",
                DEFAULT_MAX_QUERY_KEY_LENGTH,
                minimum=1,
            ),
            max_query_value_length=cls._safe_int(
                "MAX_QUERY_VALUE_LENGTH",
                DEFAULT_MAX_QUERY_VALUE_LENGTH,
                minimum=1,
            ),
            max_alerts_in_memory=cls._safe_int(
                "MAX_ALERTS_IN_MEMORY",
                DEFAULT_MAX_ALERTS_IN_MEMORY,
                minimum=1,
            ),
            log_monitor_poll_interval_seconds=cls._safe_float(
                "LOG_MONITOR_POLL_INTERVAL_SECONDS",
                DEFAULT_LOG_MONITOR_POLL_INTERVAL_SECONDS,
                minimum=0.1,
            ),
            csrf_cookie_secure=(os.getenv("CSRF_COOKIE_SECURE", "0") == "1"),
            csrf_cookie_max_age_seconds=cls._safe_int(
                "CSRF_COOKIE_MAX_AGE_SECONDS",
                DEFAULT_CSRF_COOKIE_MAX_AGE_SECONDS,
                minimum=60,
            ),
            allowed_cors_origins=allowed_origins,
        )


class InMemorySecurityState:
    """In-memory state backend.

    Replace this with a shared backend (e.g., Redis) for multi-instance deployments.
    """

    def __init__(self, max_alerts: int):
        self.ip_buckets = defaultdict(
            lambda: {
                "times": deque(),
                "blocked_until": 0.0,
                "violations": 0,
            }
        )
        self.hot_alert_buffer = deque(maxlen=max_alerts)
        self.log_tail_guard = threading.Lock()
        self.alert_guard = threading.Lock()
        self.is_tailer_live = False


class SecurityEngine:
    def __init__(
        self,
        config: SecurityConfig,
        request_logger: logging.Logger,
        error_logger: logging.Logger,
        suspicious_logger: logging.Logger,
        alert_logger: logging.Logger,
        state: Optional[InMemorySecurityState] = None,
    ):
        self.config = config
        self.request_logger = request_logger
        self.error_logger = error_logger
        self.suspicious_logger = suspicious_logger
        self.alert_logger = alert_logger
        self.state = state or InMemorySecurityState(config.max_alerts_in_memory)
        self.suspicious_patterns = [
            (name, re.compile(pattern)) for name, pattern in SUSPICIOUS_SIGNATURES
        ]

    @staticmethod
    def _decode_repeated(value: str, rounds: int = 3) -> str:
        decoded = value
        for _ in range(rounds):
            next_decoded = unquote_plus(decoded)
            if next_decoded == decoded:
                break
            decoded = next_decoded
        return decoded

    @classmethod
    def normalize_for_detection(cls, value: str) -> str:
        decoded = cls._decode_repeated(value)
        unescaped = html.unescape(decoded)
        normalized = unicodedata.normalize("NFKC", unescaped).casefold()
        return normalized.replace("\x00", "")

    def create_alert(self, source_file: str, severity: str, pattern_name: str, line: str) -> None:
        alert = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_file": source_file,
            "severity": severity,
            "pattern": pattern_name,
            "line": line.strip(),
        }
        with self.state.alert_guard:
            self.state.hot_alert_buffer.append(alert)
        self.alert_logger.warning(
            "severity=%s | pattern=%s | source=%s | line=%s",
            severity,
            pattern_name,
            source_file,
            line.strip(),
        )

    def detect_log_patterns(self, source_file: str, line: str) -> None:
        for severity, name, pattern in LOG_ALERT_RULES:
            if pattern.search(line):
                self.create_alert(source_file, severity, name, line)

    def monitor_logs_forever(self) -> None:
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
                        self.detect_log_patterns(log_filename, line)
                    file_offsets[log_filename] = f.tell()

            time.sleep(self.config.log_monitor_poll_interval_seconds)

    def start_log_monitoring(self) -> None:
        with self.state.log_tail_guard:
            if self.state.is_tailer_live:
                return
            thread = threading.Thread(target=self.monitor_logs_forever, daemon=True)
            thread.start()
            self.state.is_tailer_live = True

    def validate_query_params(self, args) -> tuple[bool, str]:
        if len(args) > self.config.max_query_params:
            return False, f"Too many query parameters; max={self.config.max_query_params}"

        for key, values in args.lists():
            if len(key) > self.config.max_query_key_length:
                return (
                    False,
                    f"Query key too long for '{key[:20]}'; max={self.config.max_query_key_length}",
                )
            if not ALLOWED_QUERY_KEY_PATTERN.match(key):
                return False, f"Invalid query key '{key}'"
            for value in values:
                if len(value) > self.config.max_query_value_length:
                    return (
                        False,
                        f"Query value too long for key '{key}'; max={self.config.max_query_value_length}",
                    )
        return True, ""

    def enforce_rate_limit(self, ip: str) -> tuple[bool, int]:
        state = self.state.ip_buckets[ip]
        now = time.time()

        if now < state["blocked_until"]:
            retry_after = int(state["blocked_until"] - now) + 1
            return False, retry_after

        times = state["times"]
        times.append(now)
        while times and (now - times[0]) > self.config.rate_limit_window_seconds:
            times.popleft()

        if len(times) > self.config.rate_limit_requests:
            state["violations"] += 1
            block_seconds = min(
                self.config.rate_limit_base_block_seconds
                * (2 ** (state["violations"] - 1)),
                self.config.rate_limit_max_block_seconds,
            )
            state["blocked_until"] = now + block_seconds
            state["times"].clear()
            return False, int(block_seconds)

        return True, 0

    def validate_csrf(self, req, ip: str) -> tuple[bool, str]:
        if req.method not in UNSAFE_METHODS:
            return True, ""

        cookie_token = req.cookies.get("csrf_token", "")
        header_token = req.headers.get("X-CSRF-Token", "")

        if not cookie_token or not header_token or cookie_token != header_token:
            self.suspicious_logger.warning(
                "CSRF validation failed | ip=%s | method=%s | path=%s",
                ip,
                req.method,
                req.path,
            )
            return False, "CSRF token missing or invalid"

        return True, ""

    def request_payload_for_detection(self, req) -> str:
        body_text = ""
        if req.method in UNSAFE_METHODS:
            body_text = req.get_data(cache=True, as_text=True) or ""

        raw_payload = " ".join(
            [
                req.path or "",
                req.query_string.decode("utf-8", errors="ignore"),
                body_text,
            ]
        )
        return self.normalize_for_detection(raw_payload)

    def find_suspicious_matches(self, payload: str) -> list[str]:
        return [name for name, pattern in self.suspicious_patterns if pattern.search(payload)]

    def alerts_snapshot(self) -> list[dict]:
        with self.state.alert_guard:
            return list(self.state.hot_alert_buffer)

    def ai_summary(self) -> dict:
        sev_weights = {"critical": 10, "high": 6, "medium": 3, "low": 1}
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        weighted_alert_score = 0

        with self.state.alert_guard:
            alerts = list(self.state.hot_alert_buffer)

        for alert in alerts:
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
        for state in self.state.ip_buckets.values():
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
                "recent_alerts": len(alerts),
                "severity_breakdown": severity_counts,
                "currently_blocked_ips": blocked_ips,
                "ips_with_recent_violations": bursty_ips,
            },
        }


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


def create_app(
    config: Optional[SecurityConfig] = None,
    engine: Optional[SecurityEngine] = None,
) -> Flask:
    os.makedirs(LOG_DIR, exist_ok=True)

    flask_app = Flask(__name__)
    cfg = config or SecurityConfig.from_env()
    flask_app.config["MAX_CONTENT_LENGTH"] = cfg.max_content_length_bytes

    request_logger = setup_logger("request_logger", "requests.log", logging.INFO)
    error_logger = setup_logger("error_logger", "errors.log", logging.ERROR)
    suspicious_logger = setup_logger("suspicious_logger", "suspicious.log", logging.WARNING)
    alert_logger = setup_logger("alert_logger", "alerts.log", logging.WARNING)

    security_engine = engine or SecurityEngine(
        config=cfg,
        request_logger=request_logger,
        error_logger=error_logger,
        suspicious_logger=suspicious_logger,
        alert_logger=alert_logger,
    )
    flask_app.extensions["security_engine"] = security_engine

    return flask_app


app = create_app()


def get_security_engine() -> SecurityEngine:
    return current_app.extensions["security_engine"]


def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


@app.before_request
def security_and_logging_hooks():
    engine = get_security_engine()
    engine.start_log_monitoring()

    ip = client_ip()
    ua = request.headers.get("User-Agent", "-")
    engine.request_logger.info("%s %s | ip=%s | ua=%s", request.method, request.path, ip, ua)

    content_length = request.content_length
    if content_length and content_length > current_app.config["MAX_CONTENT_LENGTH"]:
        engine.suspicious_logger.warning(
            "Request body too large | ip=%s | method=%s | path=%s | bytes=%d",
            ip,
            request.method,
            request.path,
            content_length,
        )
        return {"error": "request body too large"}, 413

    valid_query, reason = engine.validate_query_params(request.args)
    if not valid_query:
        engine.suspicious_logger.warning(
            "Query validation failed | ip=%s | method=%s | path=%s | reason=%s",
            ip,
            request.method,
            request.path,
            reason,
        )
        return {"error": "invalid query parameters", "reason": reason}, 400

    allowed_request, retry_after = engine.enforce_rate_limit(ip)
    if not allowed_request:
        engine.suspicious_logger.warning(
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

    valid_csrf, csrf_reason = engine.validate_csrf(request, ip)
    if not valid_csrf:
        return {"error": csrf_reason}, 403

    normalized_payload = engine.request_payload_for_detection(request)
    matched = engine.find_suspicious_matches(normalized_payload)
    if matched:
        engine.suspicious_logger.warning(
            "Pattern match | ip=%s | method=%s | path=%s | signatures=%s",
            ip,
            request.method,
            request.full_path,
            ",".join(matched),
        )


@app.after_request
def add_security_headers(response):
    engine = get_security_engine()
    origin = request.headers.get("Origin", "")
    if origin and origin in engine.config.allowed_cors_origins:
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
            secure=engine.config.csrf_cookie_secure,
            samesite="Lax",
            max_age=engine.config.csrf_cookie_max_age_seconds,
        )
    return response


@app.route("/csrf-token", methods=["GET"])
def csrf_token():
    engine = get_security_engine()
    token = request.cookies.get("csrf_token") or secrets.token_urlsafe(32)
    response = jsonify({"csrf_token": token})
    response.set_cookie(
        "csrf_token",
        token,
        httponly=False,
        secure=engine.config.csrf_cookie_secure,
        samesite="Lax",
        max_age=engine.config.csrf_cookie_max_age_seconds,
    )
    return response


@app.route("/alerts", methods=["GET", "OPTIONS"])
@app.route("/health", methods=["GET", "OPTIONS"])
@app.route("/", methods=["GET", "OPTIONS"])
def options_support():
    engine = get_security_engine()
    if request.method == "OPTIONS":
        return "", 204
    if request.path == "/":
        visitor_ip = client_ip()
        return f"Hello! Your IP {visitor_ip} has been logged."
    if request.path == "/health":
        return {"status": "ok"}, 200

    alerts = engine.alerts_snapshot()
    return {"count": len(alerts), "alerts": alerts}, 200


@app.route("/ai-insights", methods=["GET"])
def ai_insights():
    # Quick heuristic score, meant for operators and demos.
    return get_security_engine().ai_summary(), 200


@app.errorhandler(RequestEntityTooLarge)
def handle_entity_too_large(error):
    get_security_engine().suspicious_logger.warning(
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
    get_security_engine().error_logger.exception(
        "Unhandled error | method=%s | path=%s | ip=%s | error=%s",
        request.method,
        request.path,
        client_ip(),
        str(error),
    )
    return {"error": "internal server error"}, 500


if __name__ == "__main__":
    get_security_engine().start_log_monitoring()
    app.run(host="0.0.0.0", port=5000)
