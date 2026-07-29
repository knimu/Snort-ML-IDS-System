from flask import Flask, jsonify, render_template
import json
import os
import subprocess

app = Flask(__name__)

# -------------------------------------------------
# File containing IDS alerts
# -------------------------------------------------
LOG_FILE = os.path.join(
    os.path.dirname(__file__),
    "..",
    "alerts.json"
)

# -------------------------------------------------
# Dashboard UI
# -------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# -------------------------------------------------
# API : Live IDS Data
# -------------------------------------------------
@app.route("/api/data")
def get_data():

    logs = []

    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)

        except Exception as e:
            print("Error reading alerts.json:", e)
            logs = []

    # Show only latest 50 alerts
    logs = logs[-50:]

    attack_count = sum(1 for log in logs if log.get("attack", False))
    normal_count = len(logs) - attack_count

    return jsonify({
        "logs": logs,
        "attack_count": attack_count,
        "normal_count": normal_count
    })


# -------------------------------------------------
# API : Blocked IPs
# -------------------------------------------------
@app.route("/api/blocked")
def get_blocked():

    blocked_ips = []

    try:
        result = subprocess.check_output(
            ["sudo", "iptables", "-L", "INPUT", "-n"],
            stderr=subprocess.DEVNULL
        ).decode()

        for line in result.splitlines():

            if "DROP" not in line:
                continue

            parts = line.split()

            if len(parts) >= 4:
                ip = parts[3]

                if ip not in blocked_ips:
                    blocked_ips.append(ip)

    except Exception as e:
        print("Blocked IP fetch error:", e)

    return jsonify({
        "blocked_ips": blocked_ips
    })


# -------------------------------------------------
# Run Flask
# -------------------------------------------------
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
