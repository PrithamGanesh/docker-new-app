import logging
import os
import re
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


@app.before_request
def log_request_and_detect_suspicious_behavior():
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
