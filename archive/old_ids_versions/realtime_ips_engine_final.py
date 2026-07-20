import sys
import os
import time

blocked_ips = set()
last_seen = {}

print("🚀 IPS ENGINE STARTED (STATEFUL MODE)\n")

for line in sys.stdin:

    line = line.strip()

    if "->" not in line:
        continue

    try:
        parts = line.split()

        src_ip = parts[-3]
        ip = src_ip

        # prevent duplicate spam alerts
        current_time = time.time()

        if ip in last_seen:
            if current_time - last_seen[ip] < 3:
                continue

        last_seen[ip] = current_time

        print(f"🔎 DETECTED: {ip}")

        # dummy ML score (replace with your model later)
        risk_score = 0.7

        print(f"📊 Risk Score: {risk_score}")

        if risk_score > 0.5:

            if ip not in blocked_ips:

                print(f"🚫 BLOCKING: {ip}")

                os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

                blocked_ips.add(ip)

                print(f"✅ BLOCKED ONCE: {ip}")

            else:
                print(f"⚠️ Already blocked: {ip}")

    except Exception as e:
        print(f"Error: {e}")
