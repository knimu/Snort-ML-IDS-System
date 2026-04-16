import joblib
import ipaddress
import pandas as pd

# Load trained model
model = joblib.load("snort_rf_model.pkl")

# Example input (you can change IPs later)
data = {
    "src_ip": int(ipaddress.IPv4Address("192.168.1.10")),
    "dst_ip": int(ipaddress.IPv4Address("192.168.1.1")),
    "protocol": 1
}

df = pd.DataFrame([data])

# Predict
prediction = model.predict(df)

if prediction[0] == 1:
    print("🚨 Suspicious Traffic")
else:
    print("✅ Normal Traffic")
