import sys
import time
from collections import defaultdict, deque
import os
import re

print("🚀 TIME-WINDOW IDS V2 STARTED")

# store packets per IP
packet_times = defaultdict(deque)

# threshold (tune later)
THRESHOLD = 10   # packets per 5 seconds

WINDOW = 5  # seconds

def extract_ip(line):
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
    return match.group(1) if match else None


for line in sys.stdin:

    ip = extract_ip(line)
    if not ip:
        continue

    now = time.time()

    # store timestamp
    packet_times[ip].append(now)

    # remove old packets outside window
    while packet_times[ip] and now - packet_times[ip][0] > WINDOW:
        packet_times[ip].popleft()

    rate = len(packet_times[ip]) / WINDOW

    print(f"\n🔎 IP: {ip}")
    print(f"📊 Rate: {round(rate,2)} packets/sec")

    # anomaly detection
    if rate > THRESHOLD:
        print("🚨 ANOMALY DETECTED")

        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        print(f"🚫 BLOCKED: {ip}")

    else:
        print("✅ Normal traffic")
