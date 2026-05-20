import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import random

data = []

for i in range(1, 1000):
    packet_rate = i
    unique_ips = random.randint(1, 5)

    avg_interval = 1 / (packet_rate + 1)
    burst_flag = 1 if packet_rate > 150 else 0

    label = 1 if packet_rate > 120 else 0

    data.append({
        "packet_rate": packet_rate,
        "unique_src_ips": unique_ips,
        "avg_interval": avg_interval,
        "burst_flag": burst_flag,
        "label": label
    })

df = pd.DataFrame(data)

X = df[["packet_rate", "unique_src_ips", "avg_interval", "burst_flag"]]
y = df["label"]

model = RandomForestClassifier(n_estimators=120)
model.fit(X, y)

joblib.dump(model, "model.pkl")

print("✅ ADVANCED MODEL TRAINED")
