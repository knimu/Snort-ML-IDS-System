import sys
import joblib
import subprocess
import re
import time
from collections import defaultdict

model = joblib.load("snort_rf_model_enhanced.pkl")

ip_counter = defaultdict(int)
last_seen = defaultdict(float)
blocked_ips = set()

THRESHOLD = 0.85

def extract_ip(line):
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s*->', line)
    return match.group(1) if match else None


def build_features(ip, line):
    now = time.time()

    # basic behavioral features
    freq = ip_counter[ip]
    gap = now - last_seen[ip] if last_seen[ip] != 0 else 0

    # NEW FEATURES to match 7-dim model
    icmp_flag = 1 if "ICMP" in line else 0
    ipv4_flag = 1 if "ipv4" in line.lower() else 0
    multicast_flag = 1 if "224." in line else 0
    time_now = now % 10000  # simple normalized time feature

    return [[
        freq,
        gap,
        icmp_flag,
        ipv4_flag,
        multicast_flag,
        time_now,
        freq * gap
    ]]


def block_ip(ip):
    if ip in blocked_ips:
        return

    print(f"🚫 BLOCKING IP: {ip}")

    subprocess.run([
        "sudo", "iptables", "-A", "INPUT",
        "-s", ip, "-j", "DROP"
    ])

    blocked_ips.add(ip)


for line in sys.stdin:
    print("SNORT:", line.strip())

    ip = extract_ip(line)
    if not ip:
        continue

    ip_counter[ip] += 1
    last_seen[ip] = time.time()

    try:
        features = build_features(ip, line)

        prob = model.predict_proba(features)[0][1]

        print(f"🔎 {ip} | risk={prob:.2f}")

        if prob > THRESHOLD:
            block_ip(ip)

    except Exception as e:
        print("ML error:", e)
