import subprocess
import time
import re
from collections import defaultdict

ALERT_FILE = "/var/log/snort/alert_fast.txt"

THRESHOLD = 5
WINDOW_SECONDS = 10

ip_counter = defaultdict(int)
ip_last_seen = {}

def block_ip(ip):
    print(f"\n🚫 BLOCKING IP: {ip}")

    cmds = [
        ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
        ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
        ["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"],
        ["iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP"],
    ]

    for cmd in cmds:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"✅ BLOCKED: {ip}")


def extract_ip(line):
    match = re.search(r"(\d+\.\d+\.\d+\.\d+) ->", line)
    if match:
        return match.group(1)
    return None


def run():
    print("🚀 IDS + AUTO BLOCK STARTED")

    with subprocess.Popen(
        ["tail", "-F", ALERT_FILE],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    ) as proc:

        while True:
            line = proc.stdout.readline().strip()
            if not line:
                continue

            print(f"[RAW] {line}")

            ip = extract_ip(line)
            if not ip:
                continue

            now = time.time()

            # reset old counts (time window logic)
            if ip in ip_last_seen and now - ip_last_seen[ip] > WINDOW_SECONDS:
                ip_counter[ip] = 0

            ip_last_seen[ip] = now
            ip_counter[ip] += 1

            print(f"[IP] {ip} | COUNT: {ip_counter[ip]}")

            if ip_counter[ip] >= THRESHOLD:
                block_ip(ip)
                ip_counter[ip] = 0


if __name__ == "__main__":
    run()
