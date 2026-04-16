import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

print("🚀 Script started")

# Load processed dataset
df = pd.read_csv("processed_dataset.csv")
print("✅ Dataset loaded")

# Features & label
X = df[['src_ip_int', 'dst_ip_int', 'protocol']]
y = df['label']
print("✅ Features prepared")

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
print("✅ Data split")

# Train model
model = RandomForestClassifier(n_estimators=100, max_depth=10)
model.fit(X_train, y_train)
print("✅ Model trained")

# Predict on test set
y_pred = model.predict(X_test)
print("\n📊 MODEL REPORT:\n")
print(classification_report(y_test, y_pred))

# Save trained model
joblib.dump(model, "model.pkl")
print("\n🎉 Model saved as model.pkl")
