import sys
import joblib
import subprocess
import re
import time
from collections import defaultdict

# Load ML model
model = joblib.load("snort_rf_model.pkl")

# Track IP behavior
ip_counter = defaultdict(int)
last_seen = defaultdict(float)
blocked_ips = set()

# CHANGE THIS based on tuning
THRESHOLD = 0.75

def extract_ip(line):
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s*->', line)
    if match:
        return match.group(1)
    return None

def build_features(ip):
    now = time.time()

    freq = ip_counter[ip]
    gap = now - last_seen[ip] if last_seen[ip] != 0 else 0

    # 🔥 IMPORTANT FIX:
    # We pad features to match expected model input size
    # If model expects 7 features → we create 7 safe values

    features = [
        freq,          # 1
        gap,           # 2
        len(ip),       # 3 (dummy entropy proxy)
        freq * 0.5,    # 4
        gap * 0.5,     # 5
        1,             # 6 (protocol placeholder)
        0              # 7 (flag placeholder)
    ]

    return features

def block_ip(ip):
    if ip in blocked_ips:
        return

    print(f"🚫 BLOCKING IP: {ip}")
    subprocess.run([
        "sudo", "iptables", "-A", "INPUT",
        "-s", ip, "-j", "DROP"
    ])

    blocked_ips.add(ip)

# STREAM LOOP
for line in sys.stdin:
    print("SNORT:", line.strip())

    ip = extract_ip(line)

    if not ip:
        continue

    # update tracking
    ip_counter[ip] += 1
    last_seen[ip] = time.time()

    features = build_features(ip)

    try:
        # probability (better than predict)
        if hasattr(model, "predict_proba"):
            score = model.predict_proba([features])[0][1]
        else:
            score = model.predict([features])[0]

        print(f"🔎 IP: {ip} | Risk Score: {score:.2f}")

        if score >= THRESHOLD:
            block_ip(ip)

    except Exception as e:
        print("ML ERROR:", e)
