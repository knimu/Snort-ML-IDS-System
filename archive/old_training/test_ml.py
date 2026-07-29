import numpy as np
import joblib

model = joblib.load("snort_rf_model_v2.pkl")

# fake test input (7 features)
X = np.array([[500, 1, 80, 443, 10, 5, 2]])

print("Prediction:", model.predict(X))
print("Probability:", model.predict_proba(X))
