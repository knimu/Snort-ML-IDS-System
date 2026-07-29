import subprocess
import re
import sys

print("🚀 Reading Snort Alerts...")

snort_cmd = [
    "sudo",
    "snort",
    "-A",
    "fast",
    "-i",
    "ens33",
    "-c",
    "/etc/snort/snort.lua"
]

process = subprocess.Popen(
    snort_cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)

pattern = r'(\d+\.\d+\.\d+\.\d+)'

while True:

    line = process.stdout.readline()

    if not line:
        continue

    print(line.strip())

    ips = re.findall(pattern, line)

    if ips:
        print(ips[0])
        sys.stdout.flush()
