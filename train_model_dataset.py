import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

print("🚀 Training ML Model...")

# -------------------------------
# Create Dataset (Normal + Attack)
# -------------------------------

data = []

# NORMAL TRAFFIC
for i in range(500):
    packet_rate = np.random.randint(1, 50)
    same_src_count = np.random.randint(1, 5)
    avg_interval = np.random.uniform(0.5, 2)
    burst_flag = 0
    is_icmp = 1
    label = 0

    data.append([
        packet_rate,
        same_src_count,
        avg_interval,
        burst_flag,
        is_icmp,
        label
    ])

# ATTACK TRAFFIC (Ping Flood)
for i in range(500):
    packet_rate = np.random.randint(200, 1000)
    same_src_count = np.random.randint(20, 100)
    avg_interval = np.random.uniform(0.001, 0.05)
    burst_flag = 1
    is_icmp = 1
    label = 1

    data.append([
        packet_rate,
        same_src_count,
        avg_interval,
        burst_flag,
        is_icmp,
        label
    ])

# -------------------------------
# Convert to DataFrame
# -------------------------------

columns = [
    "packet_rate",
    "same_src_count",
    "avg_interval",
    "burst_flag",
    "is_icmp",
    "label"
]

df = pd.DataFrame(data, columns=columns)

# -------------------------------
# Train Model
# -------------------------------

X = df.drop("label", axis=1)
y = df["label"]

model = RandomForestClassifier(n_estimators=100)
model.fit(X, y)

# -------------------------------
# Save Model
# -------------------------------

joblib.dump(model, "model.pkl")

print("✅ MODEL TRAINED & SAVED (model.pkl)")
