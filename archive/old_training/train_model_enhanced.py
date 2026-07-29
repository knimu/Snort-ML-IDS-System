import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Load dataset
df = pd.read_csv("processed_dataset.csv")

# FINAL FEATURES
FEATURES = [
    "packet_size",
    "protocol",
    "src_port",
    "dst_port",
    "duration",
    "syn_count",
    "icmp_count"
]

X = df[FEATURES]
y = df["label"]   # attack type

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Model
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    random_state=42
)

model.fit(X_train, y_train)

print("Accuracy:", model.score(X_test, y_test))

# Save model
joblib.dump(model, "snort_rf_model_v2.pkl")

print("Model saved!")
