import sys
import joblib
import numpy as np

model = joblib.load("snort_rf_model_v2.pkl")

FEATURES = 7

def extract_features(snort_line):
    """
    Convert Snort alert → ML feature vector
    (simple heuristic version)
    """

    # default safe values
    packet_size = 100
    protocol = 1 if "ICMP" in snort_line else 0
    src_port = 0
    dst_port = 0
    duration = 1
    syn_count = 0
    icmp_count = 1 if "ICMP" in snort_line else 0

    return np.array([[packet_size, protocol, src_port, dst_port,
                      duration, syn_count, icmp_count]])

for line in sys.stdin:
    line = line.strip()
    if not line.startswith("SNORT"):
        continue

    try:
        X = extract_features(line)

        # FIX: force correct feature format
        pred = model.predict(X)[0]

        proba = model.predict_proba(X)[0].max()

        ip = line.split("->")[-1].strip().split()[0]

        print(f"🔎 IP: {ip} | ALERT: {pred} | Risk: {proba:.2f}")

        if proba > 0.75:
            print(f"🚫 BLOCKING IP: {ip}")
            # os.system(f"iptables -A INPUT -s {ip} -j DROP")

    except Exception as e:
        print("ML ERROR:", e)
