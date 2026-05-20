import pandas as pd
from collections import defaultdict
import numpy as np

print("🚀 Building features from dataset...")

df = pd.read_csv("snort_dataset.csv")

df['timestamp'] = pd.to_datetime(df['timestamp'])

df = df.sort_values(by='timestamp')

WINDOW = 10  # seconds

features = []

ip_groups = df.groupby('src_ip')

for ip, group in ip_groups:
    times = group['timestamp'].astype('int64') // 10**9

    queue = []

    for t in times:
        queue.append(t)

        # remove old
        queue = [x for x in queue if x >= t - WINDOW]

        rate = len(queue) / WINDOW

        # spike = difference from avg
        avg = np.mean(queue) if len(queue) > 0 else 0
        spike = rate - (len(queue)/WINDOW)

        # label: if alert present → attack
        label = 1 if group['alert'].iloc[0] == 1 else 0

        features.append([rate, abs(spike), label])

df_feat = pd.DataFrame(features, columns=["packet_rate", "spike", "label"])

df_feat.to_csv("processed_dataset.csv", index=False)

print("✅ Features saved → processed_dataset.csv")
