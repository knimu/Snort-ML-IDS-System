# ============================================
# REAL-TIME HYBRID IDS
# ============================================

import time
import pandas as pd
import ipaddress
import joblib
import re

print("Starting Real-Time Hybrid IDS...")

# Load trained model
model = joblib.load("snort_rf_model.pkl")

log_file = "/home/nimisha/alert_fast.txt"
# Keep track of last position (like tail -f)
with open(log_file, "r") as f:
    f.seek(0, 2)

    while True:
        line = f.readline()

        if not line:
            time.sleep(1)
            continue

        try:
            # Extract data using regex
            match = re.search(r'(\d+\.\d+\.\d+\.\d+) -> (\d+\.\d+\.\d+\.\d+)', line)
            proto_match = re.search(r'\{(.*?)\}', line)

            if match and proto_match:
                src_ip = match.group(1)
                dst_ip = match.group(2)
                protocol = proto_match.group(1)

                # Convert values
                src_ip_int = int(ipaddress.IPv4Address(src_ip))
                dst_ip_int = int(ipaddress.IPv4Address(dst_ip))
                protocol_code = 0 if protocol == "ICMP" else 1

                # Create dataframe
                sample = pd.DataFrame({
                    'src_ip': [src_ip_int],
                    'dst_ip': [dst_ip_int],
                    'protocol': [protocol_code]
                })

                # Predict
                prediction = model.predict(sample)[0]

                if prediction == 1:
                    print(f"[ALERT] Suspicious Traffic Detected: {src_ip} → {dst_ip}")
                else:
                    print(f"[NORMAL] Traffic: {src_ip} → {dst_ip}")

        except Exception as e:
            print("Error processing line:", e)
