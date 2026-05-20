import sys
import re
import os
import time
from collections import defaultdict, deque

print("🚀 IMPROVED CORE IDS ENGINE STARTED")

# -----------------------------
# STATE STORAGE (VERY IMPORTANT)
# -----------------------------

ip_stats = defaultdict(lambda: {
    "count": 0,
    "last_seen": 0,
    "blocked": False,
    "score": 0.0,
    "history": deque(maxlen=10)
})

BLOCK_THRESHOLD = 3  # adjustable
TIME_WINDOW = 10     # seconds

# -----------------------------
# EXTRACT IP FUNCTION
# -----------------------------

def extract_ip(line):
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
    return match.group(1) if match else None

# -----------------------------
# SCORING FUNCTION
# -----------------------------

def calculate_score(ip, current_time):
    data = ip_stats[ip]

    time_diff = current_time - data["last_seen"]

    # decay old activity (important fix)
    if time_diff > TIME_WINDOW:
        data["count"] = 1
    else:
        data["count"] += 1

    data["last_seen"] = current_time

    # store history (behavior tracking)
    data["history"].append(current_time)

    # simple weighted scoring
    score = data["count"] * (1 + len(data["history"]) * 0.1)

    data["score"] = score

    return score

# -----------------------------
# BLOCK FUNCTION (SAFE)
# -----------------------------

def block_ip(ip):
    if not ip_stats[ip]["blocked"]:
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        ip_stats[ip]["blocked"] = True
        print(f"🚫 BLOCKED: {ip}")
    else:
        print(f"⚠️ Already blocked: {ip}")

# -----------------------------
# MAIN LOOP
# -----------------------------

for line in sys.stdin:

    ip = extract_ip(line)
    if not ip:
        continue

    current_time = time.time()

    score = calculate_score(ip, current_time)

    print(f"\n🔎 IP: {ip}")
    print(f"📊 Score: {round(score,2)}")

    # -------------------------
    # DECISION LOGIC
    # -------------------------

    if score >= BLOCK_THRESHOLD:
        print("🚨 ANOMALY DETECTED")
        block_ip(ip)
    else:
        print("✅ Normal traffic")
