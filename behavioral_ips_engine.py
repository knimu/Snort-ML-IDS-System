import sys
import re
import time
import os
from collections import defaultdict, deque

print("🚀 BEHAVIORAL IDS STARTED (FIXED VERSION)")

# -----------------------------
# STORAGE
# -----------------------------
packet_times = defaultdict(deque)
baseline_rate = {}
blocked = set()

WINDOW = 10  # seconds
LEARN_TIME = 20  # seconds initial learning phase
start_time = time.time()

# -----------------------------
# EXTRACT IP
# -----------------------------
def get_ip(line):
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s*->', line)
    return match.group(1) if match else None

# -----------------------------
# BLOCK IP
# -----------------------------
def block(ip):
    if ip not in blocked:
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        blocked.add(ip)
        print(f"🚫 BLOCKED: {ip}")

# -----------------------------
# PROCESS
# -----------------------------
def process(line):
    ip = get_ip(line)
    if not ip:
        return

    now = time.time()

    # store timestamps
    packet_times[ip].append(now)

    # keep only last WINDOW seconds
    while packet_times[ip] and now - packet_times[ip][0] > WINDOW:
        packet_times[ip].popleft()

    current_rate = len(packet_times[ip])

    # -------------------------
    # LEARNING PHASE
    # -------------------------
    if time.time() - start_time < LEARN_TIME:
        baseline_rate[ip] = max(baseline_rate.get(ip, 0), current_rate)
        print(f"📘 Learning IP {ip} baseline = {baseline_rate[ip]}")
        return

    # -------------------------
    # ANOMALY DETECTION
    # -------------------------
    base = baseline_rate.get(ip, 1)

    score = current_rate / base

    print(f"\n🔎 IP: {ip}")
    print(f"📊 Current: {current_rate} | Baseline: {base}")
    print(f"📈 Score: {round(score, 2)}")

    if score > 2.0:
        print("🚨 ANOMALY DETECTED")
        block(ip)
    else:
        print("✅ Normal traffic")

# -----------------------------
# MAIN LOOP
# -----------------------------
for line in sys.stdin:
    process(line)
