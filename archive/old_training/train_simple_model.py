import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

data = []

# NORMAL TRAFFIC
for i in range(1, 80):
    data.append({
        "packet_rate": i,
        "unique_src_ips": 1,
        "label": 0
    })

# SUSPICIOUS
for i in range(80, 200):
    data.append({
        "packet_rate": i,
        "unique_src_ips": 1,
        "label": 1
    })

# STRONG ATTACK (DoS)
for i in range(200, 1000):
    data.append({
        "packet_rate": i,
        "unique_src_ips": 1,
        "label": 1
    })

df = pd.DataFrame(data)

X = df[["packet_rate", "unique_src_ips"]]
y = df["label"]

model = RandomForestClassifier(n_estimators=100)
model.fit(X, y)

joblib.dump(model, "model.pkl")

print("✅ NEW MODEL TRAINED (rate-based detection)")
