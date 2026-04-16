import pandas as pd
import re

log_file = "/var/log/snort/alert_fast.txt"
data = []

with open(log_file, "r") as f:
    for line in f:
        try:
            timestamp = line.split()[0]
            protocol = re.search(r'\{(.*?)\}', line).group(1)
            ips = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
            src_ip = ips[0]
            dst_ip = ips[1]
            msg = re.search(r'\] (.*?) \[', line).group(1)

            data.append([timestamp, src_ip, dst_ip, protocol, msg])
        except:
            continue

df = pd.DataFrame(data, columns=["timestamp", "src_ip", "dst_ip", "protocol", "alert"])
df.to_csv("snort_dataset.csv", index=False)
print("Dataset created!")
