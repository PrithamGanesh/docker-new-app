from flask import Flask, request
from datetime import datetime

app = Flask(__name__)


@app.route("/")
def home():
    visitor_ip = request.remote_addr
    log_entry = f"{datetime.now()} - Visitor IP: {visitor_ip}\n"

    with open("access.log", "a") as f:
        f.write(log_entry)

    return f"Hello! Your IP {visitor_ip} has been logged."

@app.route("/health")
def health():
    return {"status": "ok"}, 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)