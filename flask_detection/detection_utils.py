# flask_detection/detection_utils.py

import os
import re
import pickle
import numpy as np
import pandas as pd
import joblib
from tqdm import tqdm  

from collections import deque
from tensorflow.keras.models import load_model

from flask_detection.config import (
    GLOBAL_MODEL_PATH,
    EDGE_MODEL_PATH,
    DEVICE_MODEL_PATH,
    DATA_PATH,
    GLOBAL_FEATURES,
    EDGE_FEATURES,
    DEVICE_FEATURES,
    W_GLOBAL, W_EDGE, W_DEVICE, THRESHOLD
)
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix
)

# silence TF
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

SEQUENCE_LEN = 5

def _prep_scaler_fit(df, feats):
    scaler = StandardScaler()
    return scaler.fit_transform(df[feats].values), scaler

def run_detection_pipeline():
    """
    Runs exactly your offline “core layer” script:
     1) load + binary label
     2) fit‐transform scalers for each layer
     3) predict global, edge, device
     4) fuse + threshold
     5) evaluate metrics + save CSV
     6) yield full list of dicts
    """
    # 0) Load data & true labels
    df = pd.read_csv(DATA_PATH)
    if len(df) > 2_000_000:
        print(f"⚠️ Large dataset detected ({len(df)} rows). Processing may take time.")
    print("Dataset loaded:", df.shape)
    df["Original_Label"] = df.get("Label", pd.Series("Unknown"))
    df["Binary_Label"]   = np.where(df["Original_Label"].str.lower()=="benign", 0, 1)
    y_true = df["Binary_Label"].values
    n = len(df)

    # 1) Load models
    print("Loading XGBoost model…")
    try:
        xgbm = joblib.load(GLOBAL_MODEL_PATH)
        print("XGBoost model loaded.")
    except Exception as e:
        print(f"Error loading XGBoost model: {e}")
        raise

    print("Loading LSTM model…")
    try:
        lstm = load_model(EDGE_MODEL_PATH)
        print("LSTM model loaded.")
    except Exception as e:
        print(f"Error loading LSTM model: {e}")
        raise

    print("Loading MLP model…")
    try:
        mlp  = load_model(DEVICE_MODEL_PATH)
        print("MLP model loaded.")
    except Exception as e:
        print(f"Error loading MLP model: {e}")
        raise

    # 2) Scale & predict GLOBAL
    print("Global layer inference…")
    Xg, _ = _prep_scaler_fit(df, GLOBAL_FEATURES)
    proba_g = xgbm.predict_proba(Xg)
    conf_g = np.max(proba_g, axis=1)

    # 3) Scale & predict DEVICE
    print("Device layer inference…")
    Xd, _ = _prep_scaler_fit(df, DEVICE_FEATURES)
    conf_d = mlp.predict(Xd, batch_size=64).flatten()

    # 4) Scale & predict EDGE (batched sliding-window)
    print("Edge layer inference…")
    Xe, _ = _prep_scaler_fit(df, EDGE_FEATURES)

    sequence_length = SEQUENCE_LEN
    num_samples_edge = Xe.shape[0] - sequence_length + 1

    if num_samples_edge > 0:
        X_seq_edge = np.array([Xe[i:i+sequence_length] for i in range(num_samples_edge)])
        edge_proba = lstm.predict(X_seq_edge, batch_size=64, verbose=1)  # enable progress
        attack_conf_edge = 1.0 - edge_proba[:, 0]

        conf_e = np.zeros(Xe.shape[0])
        conf_e[:sequence_length-1] = 0.0
        conf_e[sequence_length-1:] = attack_conf_edge
    else:
        conf_e = np.zeros(Xe.shape[0])

    # 5) Align & fuse
    m = min(len(conf_g), len(conf_e), len(conf_d))
    g, e, d = conf_g[:m], conf_e[:m], conf_d[:m]
    fused = W_GLOBAL*g + W_EDGE*e + W_DEVICE*d
    pred  = (fused>THRESHOLD).astype(int)
    true  = y_true[:m]

    # 6) Evaluate only
    print("Accuracy:", accuracy_score(np.asarray(true), np.asarray(pred)))
    print("Confusion matrix:\n", confusion_matrix(np.asarray(true), np.asarray(pred)))

    # 7) Build full list
    for i in tqdm(range(m), desc="Building detection outputs"):
        yield {
            "index":           int(i),
            "global_conf":     float(g[i]),
            "edge_conf":       float(e[i]),
            "device_conf":     float(d[i]),
            "fused_score":     float(fused[i]),
            "predicted_label": int(pred[i]),
            "true_label":      int(true[i]),
            "original_label":  str(df.at[i,"Original_Label"])
        }