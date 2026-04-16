import pandas as pd
import ipaddress
import joblib

# Load enhanced model
model = joblib.load("snort_rf_model_enhanced.pkl")

# Load dataset
df = pd.read_csv("snort_dataset.csv")

# Label column (if missing)
if 'label' not in df.columns:
    df['label'] = df['alert'].apply(lambda x: 1 if "TEST ICMP ALERT" in x else 0)

# Protocol mapping
protocol_map = {"ICMP": 0, "TCP": 1, "UDP": 2}
df['protocol'] = df['protocol'].map(protocol_map)
df = df.dropna(subset=['protocol'])
df['protocol'] = df['protocol'].astype(int)

# Convert IPs
df['src_ip'] = df['src_ip'].apply(lambda x: int(ipaddress.IPv4Address(x)))
df['dst_ip'] = df['dst_ip'].apply(lambda x: int(ipaddress.IPv4Address(x)))

# Optional features
if 'src_port' not in df.columns:
    df['src_port'] = 0
if 'dst_port' not in df.columns:
    df['dst_port'] = 0
if 'payload_len' not in df.columns:
    df['payload_len'] = 0

# Time difference
df['timestamp'] = pd.to_datetime(df['timestamp'])
df = df.sort_values(['src_ip', 'timestamp'])
df['time_diff'] = df.groupby('src_ip')['timestamp'].diff().dt.total_seconds().fillna(0)

# Features for prediction
features = ['src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port', 'payload_len', 'time_diff']
X_sample = df[features].head(10)

# Predict
predictions = model.predict(X_sample)
print("Predictions for first 10 samples:")
print(predictions)
