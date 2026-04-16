# ============================================
# SNORT HYBRID IDS - MACHINE LEARNING MODULE
# ============================================

# Step 1: Import required libraries
import pandas as pd
import matplotlib.pyplot as plt
import ipaddress
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

print("Starting Snort ML Pipeline...")

# ============================================
# Step 2: Load Dataset
# ============================================
print("\nLoading dataset...")

df = pd.read_csv("snort_dataset.csv")

print("\nColumns in dataset:")
print(df.columns)

print("\nFirst 5 rows:")
print(df.head())

# ============================================
# Step 3: Data Preprocessing
# ============================================
print("\nPreprocessing data...")

# Convert IP addresses to integers
df['src_ip'] = df['src_ip'].apply(lambda x: int(ipaddress.IPv4Address(x)))
df['dst_ip'] = df['dst_ip'].apply(lambda x: int(ipaddress.IPv4Address(x)))

# Convert protocol to numeric
df['protocol'] = df['protocol'].astype('category').cat.codes

# Create binary label (1 = suspicious, 0 = normal)
df['label'] = df['alert'].apply(lambda x: 1 if "TEST ICMP ALERT" in x else 0)

# Select features
df_ml = df[['src_ip', 'dst_ip', 'protocol', 'label']]

print("\nProcessed Data Sample:")
print(df_ml.head())

# ============================================
# Step 4: Exploratory Data Analysis (EDA)
# ============================================
print("\nPerforming basic analysis...")

alert_counts = df['alert'].value_counts()
print("\nAlert Counts:")
print(alert_counts)

# Save bar chart
plt.figure(figsize=(8,5))
alert_counts.plot(kind='bar', color='skyblue')
plt.title('Snort Alert Counts by Type')
plt.xlabel('Alert Type')
plt.ylabel('Number of Alerts')
plt.tight_layout()
plt.savefig("alert_counts.png")
plt.close()

print("Alert count graph saved as alert_counts.png")

# ============================================
# Step 5: Train-Test Split
# ============================================
print("\nSplitting dataset...")

X = df_ml.drop('label', axis=1)
y = df_ml['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("Training data size:", len(X_train))
print("Testing data size:", len(X_test))

# ============================================
# Step 6: Train Machine Learning Model
# ============================================
print("\nTraining Random Forest model...")

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

print("Model training completed!")

# ============================================
# Step 7: Evaluate Model
# ============================================
print("\nEvaluating model...")

y_pred = model.predict(X_test)

print("\nAccuracy:")
print(accuracy_score(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# ============================================
# Step 8: Save Model
# ============================================
print("\nSaving model...")

joblib.dump(model, "snort_rf_model.pkl")

print("Model saved as snort_rf_model.pkl")

# ============================================
# Step 9: Test Prediction (Demo)
# ============================================
print("\nTesting model on sample input...")

sample = pd.DataFrame({
    'src_ip': [int(ipaddress.IPv4Address('192.168.10.20'))],
    'dst_ip': [int(ipaddress.IPv4Address('192.168.10.10'))],
    'protocol': [0]
})

prediction = model.predict(sample)

print("Sample Prediction (1 = attack, 0 = normal):", prediction[0])

print("\n=== PIPELINE COMPLETED SUCCESSFULLY ===")
