









import sys
import re
import time
import os
import json
import pandas as pd
import joblib
from collections import defaultdict
import traceback
# ================= SAFE IPS =================

SAFE_IPS = {
    "127.0.0.1",
    "192.168.76.129",   # IDS/Victim machine
    "8.8.8.8",
    "1.1.1.1"
}

# ================= FILES =================

MODEL_FILE = "hybrid_model.pkl"
DATASET_FILE = "dataset.csv"
LOG_FILE = "alerts.json"

# ================= LOAD ML MODEL =================

ml_model = None

if os.path.exists(MODEL_FILE):

    try:
        ml_model = joblib.load(MODEL_FILE)
        print("✅ ML MODEL LOADED")

    except Exception as e:
        print("❌ MODEL LOAD ERROR:", e)

else:
    print("⚠️ ML Model NOT FOUND")

# ================= TRACKING =================

packet_counts = defaultdict(int)
last_seen = defaultdict(float)
blocked_ips = set()

print("🚀 TRUE HYBRID IDS STARTED")

# ================= EXTRACT IP =================

def extract_ip(line):

    line = line.strip()

    # Case 1: line contains only an IP
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", line):
        return line

    # Case 2: full Snort alert line
    match = re.search(
        r'(\d+\.\d+\.\d+\.\d+)\s*->',
        line
    )

    if match:
        return match.group(1)

    return None
# ================= BLOCK IP =================

def block_ip(ip):

    if ip in blocked_ips:
        return

    print(f"⛔ BLOCKING IP: {ip}")

    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    os.system(f"sudo iptables -A OUTPUT -d {ip} -j DROP")

    blocked_ips.add(ip)

# ================= SAVE DATASET =================

def save_dataset(features, label):

    try:

        row = (
            f"{features['packet_rate']},"
            f"{features['unique_src_ips']},"
            f"{features['avg_interval']},"
            f"{features['burst_flag']},"
            f"{label}\n"
        )

        with open(DATASET_FILE, "a") as f:
            f.write(row)

        print("✅ DATASET:", row.strip())

    except Exception as e:
        print("❌ DATASET ERROR:", e)

# ================= SAVE ALERT LOG =================

def save_alert(ip, features, attack):

    print("SAVE_ALERT CALLED")

    alert = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "features": features,
        "attack": attack
    }

    try:
        data = []

        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                try:
                    data = json.load(f)
                except:
                    data = []

        data.append(alert)

        print("Writing:", os.path.abspath(LOG_FILE))

        with open(LOG_FILE, "w") as f:
            json.dump(data, f, indent=4)

        print("Finished writing")

    except Exception as e:
        import traceback
        traceback.print_exc()
# ================= MAIN LOOP =================

for line in sys.stdin:
    print("LINE RECEIVED")
    line = line.strip()
    if not line:
        continue

    print("RAW:", line)

    ip = extract_ip(line)

    if ip is None:
         continue
    # ================= SAFE IP SKIP =================

    if ip in SAFE_IPS:
        print("✅ SAFE IP SKIPPED")
        continue

    # ================= TRAFFIC FEATURES =================

    current_time = time.time()

    packet_counts[ip] += 1

    rate = packet_counts[ip]

    interval = (
        current_time - last_seen[ip]
        if last_seen[ip]
        else 1
    )

    last_seen[ip] = current_time

    burst_flag = 1 if interval < 0.05 else 0

    features = {
        "packet_rate": float(rate),
        "unique_src_ips": 1.0,
        "avg_interval": float(interval),
        "burst_flag": float(burst_flag)
    }

    print(f"📊 Rate: {rate}")
    print(f"📦 Features: {features}")

    # ================= BEHAVIORAL DETECTION =================

    behavioral_attack = (
    rate > 150 and
    interval < 0.05 and
    burst_flag == 1
)

    # ================= ML DETECTION =================

    ml_prediction = False

    if ml_model is not None:

        try:

            df = pd.DataFrame([features])

            prediction = ml_model.predict(df)[0]

            ml_prediction = bool(prediction)

        except Exception as e:
            print("❌ ML ERROR:", e)

    print(f"🤖 ML: {ml_prediction}")

    # ================= FINAL DECISION =================

    attack_detected = (
        behavioral_attack or
        (ml_prediction and rate > 100)
    )
    print("====================================")
    print("Rate:", rate)
    print("Behavior:", behavioral_attack)
    print("ML:", ml_prediction)
    print("Attack:", attack_detected)
    print("====================================")

    # ================= ATTACK =================

    if attack_detected:

        print("🚨 ATTACK DETECTED")

        save_dataset(features, 1)

        save_alert(ip, features, True)
        print("Current directory:", os.getcwd())
        print("LOG_FILE:", os.path.abspath(LOG_FILE))
        block_ip(ip)

    # ================= NORMAL =================

    else:

        print("✅ NORMAL TRAFFIC")

        save_dataset(features, 0)

        save_alert(ip, features, False)
