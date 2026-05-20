import sys
import re
import joblib
import numpy as np
from collections import defaultdict

print("🚀 ML-BASED IDS ENGINE STARTED")

# -----------------------------
# LOAD MODEL
# -----------------------------

model = joblib.load("snort_rf_model_enhanced.pkl")

# -----------------------------
# STATE TRACKING
# -----------------------------

ip_state = defaultdict(lambda: {
    "count": 0,
    "blocked": False
})

# -----------------------------
# EXTRACT IP
# -----------------------------

def extract_ip(line):
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
    return match.group(1) if match else None

# -----------------------------
# FEATURE BUILDER
# -----------------------------

def build_features(ip):
    state = ip_state[ip]

    state["count"] += 1

    # Simple features (you can improve later)
    features = np.array([[state["count"]]])

    return features

# -----------------------------
# BLOCK FUNCTION
# -----------------------------

def block_ip(ip):
    if not ip_state[ip]["blocked"]:
        import os
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        ip_state[ip]["blocked"] = True
        print(f"🚫 BLOCKED: {ip}")

# -----------------------------
# MAIN LOOP
# -----------------------------

for line in sys.stdin:

    ip = extract_ip(line)
    if not ip:
        continue

    features = build_features(ip)

    # ML PREDICTION
    prob = model.predict_proba(features)[0][1]

    print(f"\n🔎 IP: {ip}")
    print(f"📊 Risk Probability: {round(prob, 2)}")

    # -------------------------
    # DECISION
    # -------------------------

    if prob > 0.6:
        print("🚨 ANOMALY DETECTED (ML)")
        block_ip(ip)
    else:
        print("✅ Normal traffic")
