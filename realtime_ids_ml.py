import time
import datetime
import csv
import os
import re
import joblib

# --------------------------
# BLOCKING SYSTEM
# --------------------------
blocked_ips = set()

def block_ip(ip):
    if ip in blocked_ips or ip.startswith("192.168"):
        return

    print(f"[BLOCK] Blocking IP: {ip}")
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

    blocked_ips.add(ip)

    with open("blocked_ips.txt", "a") as f:
        f.write(ip + "\n")

# --------------------------
# CONFIG
# --------------------------
ALERT_FILE = "/var/log/snort/alert_fast.txt"
CSV_FILE = "ml_alerts.csv"

# --------------------------
# LOAD MODEL
# --------------------------
model = joblib.load("model.pkl")

# --------------------------
# FLOW TRACKING
# --------------------------
seen_flows = set()

# Create CSV if not exists
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Source_IP", "Dest_IP", "Protocol", "Port", "Prediction"])

# --------------------------
# PARSER
# --------------------------
def parse_alert(line):
    src_ip = dst_ip = proto = port = "N/A"

    ip_match = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
    if len(ip_match) >= 2:
        src_ip, dst_ip = ip_match[0], ip_match[1]

    proto_match = re.search(r"\{([A-Z]+)\}", line)
    if proto_match:
        proto = proto_match.group(1)

    port_match = re.search(r":(\d+)", line)
    if port_match:
        port = port_match.group(1)

    return src_ip, dst_ip, proto, port

# --------------------------
# FEATURE EXTRACTION
# --------------------------
def extract_features(src_ip, dst_ip, proto, port):
    proto_map = {"ICMP": 0, "TCP": 1, "UDP": 2}
    proto_val = proto_map.get(proto, -1)

    # Simple numeric features (upgrade later)
    port_val = int(port) if port.isdigit() else 0

    return [proto_val, port_val]

# --------------------------
# MAIN LOOP
# --------------------------
print("✅ ML IDS started - monitoring Snort alerts...")

if not os.path.exists(ALERT_FILE):
    print(f"❌ ALERT FILE {ALERT_FILE} does not exist!")
    exit(1)

with open(ALERT_FILE, "r") as f:
    f.seek(0, os.SEEK_END)

    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue

        src_ip, dst_ip, proto, port = parse_alert(line)
        flow = (src_ip, dst_ip, proto, port)

        if flow not in seen_flows:
            seen_flows.add(flow)

            features = extract_features(src_ip, dst_ip, proto, port)

            prediction = model.predict([features])[0]

            print(f"[{datetime.datetime.now()}] {src_ip} -> {dst_ip} | {proto} | Pred={prediction}")

            # 🚨 ALERT + BLOCK
            if prediction == 1:
                print("[ALERT] Suspicious Traffic Detected!")
                block_ip(src_ip)

            # Save log
            with open(CSV_FILE, "a", newline="") as csvf:
                writer = csv.writer(csvf)
                writer.writerow([datetime.datetime.now(), src_ip, dst_ip, proto, port, prediction])
