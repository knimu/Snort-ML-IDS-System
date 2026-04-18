import subprocess
import re
import time
import os

print("🚀 Hybrid IDS Started (Direct Snort Stream)...")

# Start snort process
snort_cmd = [
    "sudo", "snort",
    "-A", "fast",
    "-i", "ens37",
    "-c", "/etc/snort/snort.conf"
]

process = subprocess.Popen(snort_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

# Tracking
ip_count = {}

def extract_ip(line):
    match = re.search(r'\{ICMP\} ([0-9.]+) -> ([0-9.]+)', line)
    if match:
        return match.group(1)
    return None

while True:
    line = process.stdout.readline()

    if not line:
        continue

    if "ICMP" in line:
        print("\n🚨 ALERT:", line.strip())

        ip = extract_ip(line)
        if not ip:
            continue

        # Count burst
        ip_count[ip] = ip_count.get(ip, 0) + 1

        print("📊 Alert Burst:", ip_count[ip])

        # 🔥 THRESHOLD DETECTION
        if ip_count[ip] >= 5:
            print("🔥 ATTACK DETECTED")

            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
            print(f"🚫 Blocking IP: {ip}")

        else:
            print("✅ NORMAL TRAFFIC")
