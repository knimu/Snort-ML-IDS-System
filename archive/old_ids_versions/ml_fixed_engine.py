import sys
import joblib
import numpy as np
import re

# ==============================
# LOAD MODEL (IMPORTANT FIX)
# ==============================
model = joblib.load("snort_rf_model_enhanced.pkl")

print("🚀 ML FIXED IDS ENGINE STARTED")

# ==============================
# FEATURE STATE STORAGE
# ==============================
ip_stats = {}

# ==============================
# THRESHOLD (FOR ANOMALY)
# ==============================
THRESHOLD = 0.5   # later we can tune this

# ==============================
# FEATURE BUILDER (7 FEATURES)
# MUST MATCH TRAINING MODEL
# ==============================
def build_features(ip):
    stats = ip_stats[ip]

    count = stats["count"]
    time_window = max(stats["time_window"], 1)

    packet_rate = count / time_window

    icmp_ratio = stats["icmp"] / count
    tcp_ratio = stats["tcp"] / count
    udp_ratio = stats["udp"] / count

    avg_packet_size = stats["size_sum"] / count
    time_gap = time_window / count

    return np.array([[

        count,
        packet_rate,
        icmp_ratio,
        tcp_ratio,
        udp_ratio,
        avg_packet_size,
        time_gap
    ]])

# ==============================
# PARSE SNORT OUTPUT
# ==============================
def extract_ip(line):
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
    return match.group(1) if match else None

# ==============================
# INIT IP DATA
# ==============================
def init_ip(ip):
    if ip not in ip_stats:
        ip_stats[ip] = {
            "count": 0,
            "icmp": 0,
            "tcp": 0,
            "udp": 0,
            "size_sum": 0,
            "time_window": 5
        }

# ==============================
# MAIN LOOP
# ==============================
for line in sys.stdin:

    ip = extract_ip(line)
    if not ip:
        continue

    init_ip(ip)

    stats = ip_stats[ip]

    # simulate packet type (Snort does not always give protocol cleanly)
    if "ICMP" in line:
        stats["icmp"] += 1
    elif "TCP" in line:
        stats["tcp"] += 1
    else:
        stats["udp"] += 1

    stats["count"] += 1
    stats["size_sum"] += 64  # typical ICMP packet size assumption

    # ==============================
    # BUILD FEATURES
    # ==============================
    features = build_features(ip)

    # ==============================
    # ML PREDICTION
    # ==============================
    try:
        prob = model.predict_proba(features)[0][1]
    except:
        prob = model.predict(features)[0]

    print(f"\n🔎 IP: {ip}")
    print(f"📊 ML Score: {round(prob, 2)}")

    # ==============================
    # DECISION LOGIC
    # ==============================
    if prob > THRESHOLD:
        print("🚨 ANOMALY DETECTED")

        # BLOCK IP using iptables
        import os
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

        print(f"🚫 BLOCKED: {ip}")
    else:
        print("✅ Normal traffic")
