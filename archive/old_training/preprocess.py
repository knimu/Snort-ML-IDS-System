import pandas as pd
import ipaddress

# Load dataset
df = pd.read_csv("snort_dataset.csv")

# Convert IP to integer
def ip_to_int(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except:
        return 0

df['src_ip_int'] = df['src_ip'].apply(ip_to_int)
df['dst_ip_int'] = df['dst_ip'].apply(ip_to_int)

# Protocol encoding
df['protocol'] = df['protocol'].astype('category').cat.codes

# Better labeling
keywords = ["ICMP", "SCAN", "FLOOD", "DNS", "ATTACK"]

df['label'] = df['alert'].apply(
    lambda x: 1 if any(k in str(x).upper() for k in keywords) else 0
)

# Save processed dataset
df.to_csv("processed_dataset.csv", index=False)

print("✅ Preprocessing done!")
