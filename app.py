import logging
import os
import re
import threading
import time
from collections import defaultdict, deque

from flask import Flask, request

app = Flask(__name__)

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Basic scanner/attack signatures for lightweight suspicious-activity detection.
SUSPICIOUS_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"(?i)(union\s+select|select\s+\*|drop\s+table|or\s+1=1)"),
    re.compile(r"(?i)<script\b"),
    re.compile(r"(?i)(/etc/passwd|cmd\.exe|powershell)"),
]

REQUEST_WINDOW_SECONDS = 60
SUSPICIOUS_REQUEST_THRESHOLD = 120
ip_request_times = defaultdict(deque)
MAX_ALERTS_IN_MEMORY = 200
MONITORED_LOG_FILES = ("requests.log", "errors.log", "suspicious.log")
recent_alerts = deque(maxlen=MAX_ALERTS_IN_MEMORY)
monitor_state_lock = threading.Lock()
monitor_started = False

ALERT_PATTERNS = [
    ("critical", "unhandled_exception", re.compile(r"Unhandled error", re.IGNORECASE)),
    ("high", "signature_match", re.compile(r"Pattern match", re.IGNORECASE)),
    ("medium", "traffic_spike", re.compile(r"High request rate", re.IGNORECASE)),
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
    recent_alerts.append(alert)
    alert_logger.warning(
        "severity=%s | pattern=%s | source=%s | line=%s",
        severity,
        pattern_name,
        source_file,
        line.strip(),
    )


def detect_patterns(source_file: str, line: str) -> None:
    for severity, name, pattern in ALERT_PATTERNS:
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
    global monitor_started
    with monitor_state_lock:
        if monitor_started:
            return
        thread = threading.Thread(target=monitor_logs_forever, daemon=True)
        thread.start()
        monitor_started = True


@app.before_request
def log_request_and_detect_suspicious_behavior():
    start_log_monitoring()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ua = request.headers.get("User-Agent", "-")
    request_logger.info("%s %s | ip=%s | ua=%s", request.method, request.path, ip, ua)

    full_payload = " ".join(
        [
            request.path or "",
            request.query_string.decode("utf-8", errors="ignore"),
            request.get_data(cache=True, as_text=True) or "",
        ]
    )

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

    now = time.time()
    times = ip_request_times[ip]
    times.append(now)
    while times and (now - times[0]) > REQUEST_WINDOW_SECONDS:
        times.popleft()

    if len(times) > SUSPICIOUS_REQUEST_THRESHOLD:
        suspicious_logger.warning(
            "High request rate | ip=%s | count=%d | window=%ds",
            ip,
            len(times),
            REQUEST_WINDOW_SECONDS,
        )


@app.errorhandler(Exception)
def log_unhandled_error(error):
    error_logger.exception(
        "Unhandled error | method=%s | path=%s | ip=%s | error=%s",
        request.method,
        request.path,
        request.headers.get("X-Forwarded-For", request.remote_addr),
        str(error),
    )
    return {"error": "internal server error"}, 500


@app.route("/")
def home():
    visitor_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    return f"Hello! Your IP {visitor_ip} has been logged."


@app.route("/health")
def health():
    return {"status": "ok"}, 200


@app.route("/alerts")
def alerts():
    return {
        "count": len(recent_alerts),
        "alerts": list(recent_alerts),
    }, 200


if __name__ == "__main__":
    start_log_monitoring()
    app.run(host="0.0.0.0", port=5000)
