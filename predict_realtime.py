import pandas as pd
import joblib
import ipaddress
import time
import re

# ----------------------------
# Load trained model
# ----------------------------
model = joblib.load("snort_rf_model_enhanced.pkl")

# ----------------------------
# Helper function: parse a single Snort alert line
# ----------------------------
def parse_alert_line(line):
    """
    Parses a Snort alert line and returns a dictionary with features.
    Returns None if line cannot be parsed.
    """
    try:
        # Extract protocol
        proto_match = re.search(r"\{(\w+)\}", line)
        protocol = proto_match.group(1) if proto_match else None
        protocol_map = {"ICMP": 0, "TCP": 1, "UDP": 2}
        if protocol not in protocol_map:
            return None
        protocol_val = protocol_map[protocol]

        # Extract IPs
        ip_match = re.search(r"([\d:.]+)\s*->\s*([\d:.]+)", line)
        if not ip_match:
            return None
        src_ip_raw, dst_ip_raw = ip_match.groups()

        # Convert IP to integer (works for IPv4 only; IPv6 will raise ValueError)
        try:
            src_ip = int(ipaddress.IPv4Address(src_ip_raw))
            dst_ip = int(ipaddress.IPv4Address(dst_ip_raw))
        except ipaddress.AddressValueError:
            return None  # skip IPv6 or invalid IPs

        # Return features dictionary
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol_val
        }

    except Exception as e:
        print(f"Skipping line due to parsing error: {line.strip()} ({e})")
        return None

# ----------------------------
# Real-time monitoring loop
# ----------------------------
alerts_file = "alert_fast.txt"

print("Starting real-time Snort alert monitoring...")

with open(alerts_file, "r") as f:
    f.seek(0, 2)  # Move to the end of the file

    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)  # Wait for new data
            continue
        parsed = parse_alert_line(line)
        if parsed:
            df = pd.DataFrame([parsed])
            # Make sure columns match model features
            X_sample = df[['src_ip', 'dst_ip', 'protocol']]
            try:
                pred = model.predict(X_sample)
                print(f"New alert prediction: {pred[0]}")
            except Exception as e:
                print(f"Error during prediction: {e}")
