import sys
import time
import os
import re
import numpy as np
from collections import defaultdict, deque
import pickle

# ---------------- CONFIG ----------------
TIME_WINDOW = 5
THRESHOLD_RATE = 3

# ---------------- LOAD ML MODEL ----------------
model = pickle.load(open("snort_rf_model.pkl", "rb"))

# ---------------- STORAGE ----------------
ip_packets = defaultdict(deque)
blocked_ips = set()

# ---------------- IP EXTRACTION ----------------
def extract_ip(line):
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
    return match.group(1) if match else None

# ---------------- BLOCK ----------------
def block_ip(ip):
    if ip not in blocked_ips:
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        blocked_ips.add(ip)
        print(f"🚫 BLOCKED: {ip}")

# ---------------- FEATURE BUILDER (IMPORTANT) ----------------
def build_features(ip, rate, count):
    """
    Convert real traffic → ML 7 features
    """

    icmp_ratio = 0.6 if rate > 3 else 0.2
    tcp_ratio = 0.3
    udp_ratio = 0.1

    avg_packet_size = 64 + (rate * 10)
    time_gap = 1 / (rate + 0.1)

    return [
        count,
        rate,
        icmp_ratio,
        tcp_ratio,
        udp_ratio,
        avg_packet_size,
        time_gap
    ]

# ---------------- START ----------------
print("🚀 HYBRID IDS V4 STARTED (ML + BEHAVIORAL)")

for line in sys.stdin:

    ip = extract_ip(line)
    if not ip:
        continue

    now = time.time()

    ip_packets[ip].append(now)

    # sliding window
    while ip_packets[ip] and now - ip_packets[ip][0] > TIME_WINDOW:
        ip_packets[ip].popleft()

    count = len(ip_packets[ip])
    rate = count / TIME_WINDOW

    # ---------------- BEHAVIORAL CHECK ----------------
    anomaly_behavior = rate > THRESHOLD_RATE

    # ---------------- ML FEATURES ----------------
    features = build_features(ip, rate, count)
    features = np.array(features).reshape(1, -1)

    # ---------------- ML PREDICTION ----------------
    try:
        ml_score = model.predict_proba(features)[0][1]
    except:
        ml_score = model.predict(features)[0]

    # ---------------- FINAL DECISION ----------------
    final_score = (ml_score * 0.6) + (rate / 10 * 0.4)

    print(f"\n🔎 IP: {ip}")
    print(f"📊 Rate: {rate:.2f}")
    print(f"🤖 ML Score: {ml_score:.2f}")
    print(f"📊 Final Score: {final_score:.2f}")

    if final_score > 0.6 or anomaly_behavior:
        print("🚨 ATTACK DETECTED")
        block_ip(ip)
    else:
        print("✅ NORMAL TRAFFIC")
