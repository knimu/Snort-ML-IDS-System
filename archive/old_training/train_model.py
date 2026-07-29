import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

print("🚀 Training ML model...")

df = pd.read_csv("processed_dataset.csv")

X = df[["packet_rate", "spike"]]
y = df["label"]

model = RandomForestClassifier(n_estimators=50)
model.fit(X, y)

joblib.dump(model, "clean_model.pkl")

print("✅ Model trained and saved as clean_model.pkl")
