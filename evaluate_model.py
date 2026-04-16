import pandas as pd
import joblib
import ipaddress
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Load trained model
model = joblib.load("snort_rf_model.pkl")

# Load dataset
df = pd.read_csv("snort_dataset.csv")

# ✅ Create label column if it doesn't exist
if 'label' not in df.columns:
    df['label'] = df['alert'].apply(lambda x: 1 if "TEST ICMP ALERT" in x else 0)

# ✅ Fixed protocol mapping
protocol_map = {"ICMP": 0, "TCP": 1, "UDP": 2}
df['protocol'] = df['protocol'].map(protocol_map)
df = df.dropna(subset=['protocol'])
df['protocol'] = df['protocol'].astype(int)

# ✅ Convert IPs to integers
df['src_ip'] = df['src_ip'].apply(lambda x: int(ipaddress.IPv4Address(x)))
df['dst_ip'] = df['dst_ip'].apply(lambda x: int(ipaddress.IPv4Address(x)))

# Features and labels
X = df[['src_ip', 'dst_ip', 'protocol']]
y = df['label']

# Predict
y_pred = model.predict(X)

# Evaluation
print("Accuracy:", accuracy_score(y, y_pred))
print("\nClassification Report:\n", classification_report(y, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y, y_pred))
