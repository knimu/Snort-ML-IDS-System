import time
import pandas as pd
import joblib

# Load your trained ML model
model = joblib.load("snort_rf_model.pkl")
print("✅ ML Model loaded")

# Path to Snort alert log
log_file = "/var/log/snort/alert_fast.txt"

# Keep track of already processed lines
seen_lines = set()

print("🚀 Monitoring Snort alerts... Press Ctrl+C to stop")
try:
    while True:
        with open(log_file, "r") as f:
            lines = f.readlines()
        for line in lines:
            if line in seen_lines:
                continue
            seen_lines.add(line)

            # Example: parse source IP, dest IP, protocol from log
            try:
                parts = line.split()
                src_ip = parts[-3]
                dst_ip = parts[-1]
                proto = parts[-2].strip("{}")  # e.g., {IP} -> IP
                # For ML, you may need numeric encoding:
                # protocol: IP=0, ICMP=1, TCP=2, UDP=3
                proto_code = 0 if proto == "IP" else 1  # adjust if needed
                # TODO: encode IPs same way as training
                # Example: simple int conversion
                src_ip_int = int("".join([f"{int(x):03}" for x in src_ip.split(".")]))
                dst_ip_int = int("".join([f"{int(x):03}" for x in dst_ip.split(".")]))
                
                # Build ML feature vector
                X_new = pd.DataFrame([[src_ip_int, dst_ip_int, proto_code]], columns=["src_ip","dst_ip","protocol"])
                pred = model.predict(X_new)[0]
                if pred == 1:
                    print("[ALERT] Suspicious Traffic Detected:", line.strip())
            except Exception as e:
                # Ignore lines that cannot be parsed
                continue

        time.sleep(1)
except KeyboardInterrupt:
    print("🛑 Stopped monitoring")
