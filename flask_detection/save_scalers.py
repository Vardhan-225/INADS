# save_scalers.py

import pandas as pd
import pickle
from sklearn.preprocessing import StandardScaler
from flask_detection.config import (
    DATA_PATH, EDGE_FEATURES, DEVICE_FEATURES,
    SCALER_EDGE_PATH, SCALER_DEVICE_PATH
)

df = pd.read_csv(DATA_PATH)

# Fit and save Edge scaler
edge_scaler = StandardScaler()
edge_scaler.fit(df[EDGE_FEATURES])
with open(SCALER_EDGE_PATH, "wb") as f:
    pickle.dump(edge_scaler, f)
print(f"✅ Edge scaler saved to {SCALER_EDGE_PATH}")

# Fit and save Device scaler
device_scaler = StandardScaler()
device_scaler.fit(df[DEVICE_FEATURES])
with open(SCALER_DEVICE_PATH, "wb") as f:
    pickle.dump(device_scaler, f)
print(f"✅ Device scaler saved to {SCALER_DEVICE_PATH}")