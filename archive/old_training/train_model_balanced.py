import pandas as pd
import ipaddress
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

# Load dataset
df = pd.read_csv("snort_dataset.csv")

# Create label column if missing
if 'label' not in df.columns:
    df['label'] = df['alert'].apply(lambda x: 1 if "TEST ICMP ALERT" in x else 0)

# Map protocol to numeric
protocol_map = {"ICMP": 0, "TCP": 1, "UDP": 2}
df['protocol'] = df['protocol'].map(protocol_map)
df = df.dropna(subset=['protocol'])
df['protocol'] = df['protocol'].astype(int)

# Convert IP addresses to integers
df['src_ip'] = df['src_ip'].apply(lambda x: int(ipaddress.IPv4Address(x)))
df['dst_ip'] = df['dst_ip'].apply(lambda x: int(ipaddress.IPv4Address(x)))

# Add optional features
if 'src_port' not in df.columns:
    df['src_port'] = 0
if 'dst_port' not in df.columns:
    df['dst_port'] = 0
if 'payload_len' not in df.columns:
    df['payload_len'] = 0

# Time difference feature
df['timestamp'] = pd.to_datetime(df['timestamp'])
df = df.sort_values(['src_ip', 'timestamp'])
df['time_diff'] = df.groupby('src_ip')['timestamp'].diff().dt.total_seconds().fillna(0)

# Features and labels
features = ['src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port', 'payload_len', 'time_diff']
X = df[features]
y = df['label']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Random Forest with balanced classes
model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
model.fit(X_train, y_train)

# Evaluate model
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))

# Save the enhanced model
joblib.dump(model, "snort_rf_model_enhanced.pkl")
print("\nModel saved as snort_rf_model_enhanced.pkl")
