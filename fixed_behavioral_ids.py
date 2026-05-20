import time
import subprocess
from collections import defaultdict, deque
import re

# ==============================
# CONFIG
# ==============================
WINDOW = 10              # seconds
THRESHOLD = 3.0          # anomaly score threshold
SPIKE_RATE = 50          # direct spike detection (important!)

traffic = defaultdict(deque)
baseline = defaultdict(float)
blocked_ips = set()

print("🚀 FIXED BEHAVIORAL IDS STARTED")

# ==============================
# EXTRACT IP FROM SNORT LOG
# ==============================
def extract_ip(line):
    ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', line)
    if len(ips) >= 2:
        return ips[-2]   # source IP
    return None

# ==============================
# BLOCK IP USING IPTABLES
# ==============================
def block_ip(ip):
    if ip in blocked_ips:
        print(f"⚠️ Already blocked: {ip}")
        return
    subprocess.call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    blocked_ips.add(ip)
    print("🚫 BLOCKED:", ip)

# ==============================
# MAIN LOOP (READ FROM SNORT PIPE)
# ==============================
import sys

for line in sys.stdin:
    ip = extract_ip(line)
    if not ip:
        continue

    now = time.time()

    # ==============================
    # TRACK PACKETS IN TIME WINDOW
    # ==============================
    q = traffic[ip]
    q.append(now)

    while q and now - q[0] > WINDOW:
        q.popleft()

    rate = len(q) / WINDOW   # packets/sec

    # ==============================
    # BASELINE (CORRECT LOGIC)
    # ==============================
    if baseline[ip] == 0:
        baseline[ip] = rate
    else:
        baseline[ip] = 0.8 * baseline[ip] + 0.2 * rate

    # ==============================
    # SCORE CALCULATION
    # ==============================
    score = rate / (baseline[ip] + 0.001)

    # ==============================
    # OUTPUT
    # ==============================
    print(f"\n🔎 IP: {ip}")
    print(f"📊 Rate: {rate:.2f} | Baseline: {baseline[ip]:.2f}")
    print(f"📈 Score: {score:.2f}")

    # ==============================
    # DETECTION LOGIC (IMPORTANT)
    # ==============================
    if rate > SPIKE_RATE:
        print("🔥 SPIKE ATTACK DETECTED")
        block_ip(ip)

    elif score > THRESHOLD:
        print("🚨 ANOMALY DETECTED")
        block_ip(ip)

    else:
        print("✅ Normal traffic")
