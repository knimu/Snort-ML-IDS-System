import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Load dataset
df = pd.read_csv("training_data.csv")

FEATURES = [
    "src_ip_numeric",
    "dst_ip_numeric",
    "src_port",
    "dst_port",
    "protocol",
    "packet_size",
    "tcp_flags",
    "syn_count",
    "icmp_count",
    "flow_duration"
]

X = df[FEATURES]
y = df["label"]   # normal, ddos, icmp_flood, scan, brute_force

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    random_state=42
)

model.fit(X_train, y_train)

print("✅ Features expected:", model.n_features_in_)

joblib.dump(model, "snort_rf_model_v2.pkl")

print("✅ Model saved successfully")
