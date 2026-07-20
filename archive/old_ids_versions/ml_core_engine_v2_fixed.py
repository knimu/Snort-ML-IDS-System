import sys
import re
import joblib
import numpy as np
from collections import defaultdict

# Load trained ML model
model = joblib.load("snort_rf_model_enhanced.pkl")

# Track IP behavior
ip_history = defaultdict(list)

# Store blocked IPs
blocked_ips = set()

# Threshold for anomaly detection
THRESHOLD = 0.7

print("🚀 ML CORE IDS ENGINE V2 FIXED STARTED")

# -----------------------------
# Extract IP from Snort output
# -----------------------------
def extract_ip(line):
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
    return match.group(1) if match else None

# -----------------------------
# Feature Engineering (7 features EXACT MATCH)
# -----------------------------
def extract_features(ip):
    history = ip_history[ip]

    packet_count = len(history) + 1

    duration = 1
    src_bytes = packet_count * 120
    dst_bytes = packet_count * 90

    protocol = 1   # ICMP (ping simulation)
    flags = 0

    burst_rate = packet_count / 5

    return [
        packet_count,
        duration,
        src_bytes,
        dst_bytes,
        protocol,
        flags,
        burst_rate
    ]

# -----------------------------
# MAIN LOOP (Snort → Python)
# -----------------------------
for line in sys.stdin:

    ip = extract_ip(line)
    if not ip:
        continue

    # update history
    ip_history[ip].append(1)

    # extract features
    features = extract_features(ip)

    X = np.array([features])

    # ML prediction
    try:
        prob = model.predict_proba(X)[0][1]
    except:
        prob = model.predict(X)[0]

    print(f"\n🔎 IP: {ip}")
    print(f"📊 ML Score: {round(prob, 2)}")

    # Decision logic
    if prob > THRESHOLD:
        if ip not in blocked_ips:
            print(f"🚨 ANOMALY DETECTED")
            print(f"🚫 BLOCKING: {ip}")

            # block using iptables
            import os
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

            blocked_ips.add(ip)
        else:
            print(f"⚠️ Already blocked: {ip}")
    else:
        print("✅ Normal traffic")
