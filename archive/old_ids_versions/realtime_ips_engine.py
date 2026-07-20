import sys
import joblib
import subprocess
import re
import time
import pandas as pd
from collections import defaultdict

# Load trained model
model = joblib.load("snort_rf_model.pkl")

# Track IP behavior
ip_counter = defaultdict(int)
last_seen = defaultdict(float)

# -----------------------------
# Extract IP from Snort line
# -----------------------------
def extract_ip(line):
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s*->', line)
    if match:
        return match.group(1)
    return None

# -----------------------------
# Feature engineering (MUST MATCH MODEL = 3 FEATURES)
# -----------------------------
def build_features(ip):
    now = time.time()

    freq = ip_counter[ip]
    last = last_seen[ip]
    gap = now - last if last != 0 else 0

    # 3rd feature (behavior intensity score)
    intensity = freq / (gap + 1)

    return [freq, gap, intensity]

# -----------------------------
# Block IP using iptables
# -----------------------------
def block_ip(ip):
    print(f"\n🚫 BLOCKING IP: {ip}\n")

    subprocess.run([
        "sudo", "iptables", "-A", "INPUT",
        "-s", ip, "-j", "DROP"
    ])

# -----------------------------
# STREAM PROCESSING
# -----------------------------
print("🚀 Real-Time IDS + IPS Engine Started...\n")

for line in sys.stdin:
    line = line.strip()
    print("SNORT:", line)

    ip = extract_ip(line)

    if ip:
        # update behavior tracking
        ip_counter[ip] += 1
        last_seen[ip] = time.time()

        features = build_features(ip)

        try:
            # FIX: use DataFrame to match sklearn training format
            pred = model.predict(pd.DataFrame([features]))[0]

            if pred == 1:
                block_ip(ip)

        except Exception as e:
            print("❌ ML error:", e)
