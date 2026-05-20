from flask import Flask, jsonify, render_template
import json
import os
import subprocess

app = Flask(__name__)

# ─── FILE PATH ─────────────────────────────
LOG_FILE = "../logs.json"


# ─── ROUTE: UI ─────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


# ─── ROUTE: LIVE DATA ──────────────────────
@app.route("/api/data")
def get_data():

    logs = []

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()[-50:]

            for line in lines:
                try:
                    logs.append(json.loads(line.strip()))
                except:
                    continue

    attack_count = sum(1 for log in logs if log.get("attack") == True)
    normal_count = len(logs) - attack_count

    return jsonify({
        "logs": logs,
        "attack_count": attack_count,
        "normal_count": normal_count
    })


# ─── ROUTE: BLOCKED IPS ────────────────────
@app.route("/api/blocked")
def get_blocked():

    blocked_ips = []

    try:
        result = subprocess.check_output(
            ["sudo", "iptables", "-L", "INPUT", "-n"],
            stderr=subprocess.DEVNULL
        ).decode()

        for line in result.split("\n"):
            if "DROP" in line:
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


# ─── MAIN ──────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)
