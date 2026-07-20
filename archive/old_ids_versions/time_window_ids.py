import sys
import re
import time
import os
from collections import defaultdict, deque

print("🚀 TIME-WINDOW BEHAVIORAL IDS STARTED")

# ----------------------------
# CONFIGURATION
# ----------------------------
WINDOW_SIZE = 5   # seconds
THRESHOLD = 5     # packets per window = attack

# ----------------------------
# STORAGE: IP → timestamps
# ----------------------------
traffic_window = defaultdict(deque)

# ----------------------------
# EXTRACT IP
# ----------------------------
def extract_ip(line):
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
    if match:
        return match.group(1)
    return None

# ----------------------------
# MAIN LOOP
# ----------------------------
for line in sys.stdin:

    ip = extract_ip(line)
    if not ip:
        continue

    now = time.time()

    # add timestamp
    traffic_window[ip].append(now)

    # remove old packets outside window
    while traffic_window[ip] and (now - traffic_window[ip][0]) > WINDOW_SIZE:
        traffic_window[ip].popleft()

    # calculate packet rate
    rate = len(traffic_window[ip]) / WINDOW_SIZE

    print(f"\n🔎 IP: {ip}")
    print(f"📊 Rate: {round(rate, 2)} packets/sec")

    # ----------------------------
    # DETECTION LOGIC
    # ----------------------------
    if rate > THRESHOLD:
        print("🚨 ANOMALY DETECTED (PING FLOOD / HIGH RATE)")

        # BLOCK IP
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        print(f"🚫 BLOCKED: {ip}")

    else:
        print("✅ Normal traffic")
