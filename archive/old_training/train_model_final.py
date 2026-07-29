import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

# Generate synthetic training data

data = []

# NORMAL traffic
for _ in range(500):
    data.append([
        np.random.randint(1, 20),     # packet_rate
        np.random.uniform(0.5, 2),    # avg_interval
        np.random.randint(1, 3),      # unique_src_ips
        np.random.randint(1, 10),     # same_src_count
        1,                            # is_icmp
        5,                            # time_window
        0,                            # burst_flag
        0                             # label (normal)
    ])

# ATTACK traffic
for _ in range(500):
    data.append([
        np.random.randint(100, 3000), # packet_rate (HIGH)
        np.random.uniform(0.001, 0.05), # avg_interval (VERY LOW)
        np.random.randint(1, 2),
        np.random.randint(100, 500),
        1,
        5,
        1,                            # burst_flag
        1                             # label (attack)
    ])

df = pd.DataFrame(data, columns=[
    "packet_rate",
    "avg_interval",
    "unique_src_ips",
    "same_src_count",
    "is_icmp",
    "time_window",
    "burst_flag",
    "label"
])

X = df.drop("label", axis=1)
y = df["label"]

model = RandomForestClassifier(n_estimators=100)
model.fit(X, y)

joblib.dump(model, "snort_rf_model_enhanced.pkl")

print("✅ NEW MODEL TRAINED WITH REAL FEATURES")
