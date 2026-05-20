import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# ================= LOAD DATASET =================

df = pd.read_csv("dataset.csv")

print("\n📊 DATASET LOADED")
print(df.head())

# ================= FEATURES =================

X = df[
    [
        "packet_rate",
        "unique_src_ips",
        "avg_interval",
        "burst_flag"
    ]
]

# ================= LABEL =================

y = df["label"]

# ================= TRAIN TEST SPLIT =================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# ================= MODEL =================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

# ================= TRAIN =================

print("\n🚀 TRAINING MODEL...")

model.fit(X_train, y_train)

# ================= TEST =================

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print(f"\n✅ ACCURACY: {accuracy * 100:.2f}%")

# ================= SAVE =================

joblib.dump(model, "hybrid_model.pkl")

print("\n✅ MODEL SAVED: hybrid_model.pkl")
