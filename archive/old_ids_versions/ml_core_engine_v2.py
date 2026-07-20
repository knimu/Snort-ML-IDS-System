import sys
import re
import joblib
from collections import defaultdict

# Load model
model = joblib.load("snort_rf_model_enhanced.pkl")

# Track IP history
ip_history = defaultdict(list)
blocked_ips = set()

THRESHOLD = 0.7   # probability threshold

print("🚀 ML CORE IDS ENGINE V2 STARTED")

def extract_ip(line):
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
    return match.group(1) if match else None

def extract_features(ip):
    """
    Simple behavioral features per IP
    """
    history = ip_history[ip]

    packet_count = len(history)

    # last activity time difference simulation
    burst_score = packet_count / 10

    return [packet_count, burst_score]

for line in sys.stdin:
    ip = extract_ip(line)

    if not ip:
        continue

    ip_history[ip].append(1)

    features = extract_features(ip)

    # ML prediction
    try:
        prob = model.predict_proba([features])[0][1]
    except:
        prob = model.predict([features])[0]

    print(f"\n🔎 IP: {ip}")
    print(f"📊 ML Score: {round(prob, 2)}")

    if prob > THRESHOLD:
        if ip not in blocked_ips:
            print(f"🚨 ATTACK DETECTED")
            print(f"🚫 BLOCKING: {ip}")
            blocked_ips.add(ip)
        else:
            print(f"⚠️ Already blocked: {ip}")
    else:
        print("✅ Normal traffic")
