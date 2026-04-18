import sys
import re
import joblib
import numpy as np
from collections import defaultdict

model = joblib.load("snort_rf_model_enhanced.pkl")

FEATURES = [
    "packet_size",
    "protocol",
    "src_port",
    "dst_port",
    "duration",
    "syn_count",
    "icmp_count"
]

traffic_stats = defaultdict(lambda: {
    "packet_size": 0,
    "syn_count": 0,
    "icmp_count": 0
})

def extract_ip(line):
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
    return match.group(1) if match else None

def build_features(ip):
    stats = traffic_stats[ip]

    return np.array([[
        stats["packet_size"],
        1,              # protocol ICMP = 1 (example)
        0,              # src_port placeholder
        0,              # dst_port placeholder
        1,              # duration placeholder
        stats["syn_count"],
        stats["icmp_count"]
    ]])

print("🚀 Hybrid IDS Engine Running...")

for line in sys.stdin:
    ip = extract_ip(line)

    if not ip:
        continue

    # update fake stats (you can improve later)
    traffic_stats[ip]["packet_size"] += 60
    traffic_stats[ip]["icmp_count"] += 1

    X = build_features(ip)

    try:
        risk = model.predict_proba(X)[0][1]
    except:
        print("ML ERROR: feature mismatch")
        continue

    print(f"🔎 IP: {ip} | Risk Score: {risk:.2f}")

    if risk > 0.7:
        print(f"🚫 BLOCKING IP: {ip}")
        import os
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
