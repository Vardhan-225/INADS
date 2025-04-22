import os
import numpy as np
import pandas as pd
import joblib
import xgboost as xgb
import tensorflow as tf
from tensorflow.keras.models import load_model

from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_curve, auc

from flask_detection.config import GLOBAL_MODEL, EDGE_MODEL, DEVICE_MODEL, DATA_PATH, GLOBAL_FEATURES, EDGE_FEATURES, DEVICE_FEATURES

def run_detection_pipeline():
    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH)
    print("Dataset loaded. Shape:", df.shape)

    df["Original_Label"] = df["Label"] if "Label" in df.columns else "Unknown"

    if "Binary_Label" not in df.columns:
        df["Binary_Label"] = np.where(df["Label"].str.lower() == "benign", 0, 1)

    print("🔍 Loading model files:")
    print(" - Global Model:", GLOBAL_MODEL, "| Modified:", os.path.getmtime(GLOBAL_MODEL))
    print(" - Edge Model:", EDGE_MODEL, "| Modified:", os.path.getmtime(EDGE_MODEL))
    print(" - Device Model:", DEVICE_MODEL, "| Modified:", os.path.getmtime(DEVICE_MODEL))

    print("Loading models...")
    xgb_global = joblib.load(GLOBAL_MODEL)
    edge_lstm = load_model(EDGE_MODEL)
    device_mlp = load_model(DEVICE_MODEL)

    print("Generating predictions...")

    # Global Layer
    X_global = df[GLOBAL_FEATURES].values
    y_pred_proba_global = xgb_global.predict_proba(X_global)
    attack_conf_global = 1.0 - y_pred_proba_global[:, 0]

    # Edge Layer (LSTM)
    X_edge = df[EDGE_FEATURES].values
    scaler_edge = StandardScaler()
    X_edge_scaled = scaler_edge.fit_transform(X_edge)
    sequence_length = 5
    num_samples_edge = X_edge_scaled.shape[0] - sequence_length + 1
    X_seq_edge = np.array([X_edge_scaled[i : i + sequence_length] for i in range(num_samples_edge)])
    edge_proba = edge_lstm.predict(X_seq_edge, batch_size=64)
    
    print("Edge LSTM raw output (first 10):", edge_proba[:10])
    print("Max edge confidence:", np.max(edge_proba))
    print("Min edge confidence:", np.min(edge_proba))
    print("Mean edge confidence:", np.mean(edge_proba))
    
    attack_conf_edge = 1.0 - edge_proba[:, 0]
    attack_conf_edge_aligned = np.zeros(X_edge.shape[0])
    attack_conf_edge_aligned[:sequence_length - 1] = np.nan
    attack_conf_edge_aligned[sequence_length - 1:] = attack_conf_edge
    attack_conf_edge_aligned = np.nan_to_num(attack_conf_edge_aligned, nan=0.0)

    print("Edge confidence after alignment (first 10):", attack_conf_edge_aligned[:10])

    # Device Layer (MLP)
    X_device = df[DEVICE_FEATURES].values
    scaler_device = StandardScaler()
    X_device_scaled = scaler_device.fit_transform(X_device)
    device_proba = device_mlp.predict(X_device_scaled, batch_size=64).flatten()
    attack_conf_device = device_proba

    print("[Device] Confidence stats — max:", np.max(device_proba), "min:", np.min(device_proba), "mean:", np.mean(device_proba))

    # Fusion
    w_global, w_edge, w_device = 0.3, 0.3, 0.4
    fused_score = (w_global * attack_conf_global +
                   w_edge * attack_conf_edge_aligned +
                   w_device * attack_conf_device)
    fused_label = (fused_score > 0.5).astype(int)

    print("Fused score stats — max:", np.max(fused_score), "min:", np.min(fused_score), "mean:", np.mean(fused_score))

    y_true = df["Binary_Label"].values
    assert len(y_true) == len(fused_label)

    acc_core = accuracy_score(y_true, fused_label)
    print(f"\nFused accuracy: {acc_core:.4f}")
    print("Classification Report:")
    print(classification_report(y_true, fused_label, target_names=["Benign", "Attack"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_true, fused_label))

    preview_range = slice(0, 3)
    print("Sample outputs:")
    print("Global conf:", [float(val) for val in attack_conf_global[preview_range]])
    print("Edge conf:", [float(val) for val in attack_conf_edge_aligned[preview_range]])
    print("Device conf:", [float(val) for val in attack_conf_device[preview_range]])
    print("Fused scores:", [float(val) for val in fused_score[preview_range]])
    print("Predicted labels:", [int(val) for val in fused_label[preview_range]])
    print("True labels:", [int(val) for val in y_true[preview_range]])
    
    top_n = 10
    top_indices = np.argsort(fused_score)[::-1][:top_n]

    print("🔍 Top fused indices:", top_indices)
    print("🔍 Top fused scores:", fused_score[top_indices])

    results = []
    for i in top_indices:
        results.append({
            "index": int(i),
            "global_conf": float(attack_conf_global[i]),
            "edge_conf": float(attack_conf_edge_aligned[i]),
            "device_conf": float(attack_conf_device[i]),
            "fused_score": float(fused_score[i]),
            "predicted_label": int(fused_label[i]),
            "true_label": int(y_true[i]),
            "original_label": str(df["Original_Label"].iloc[i])
        })

    print(f"✔️ Pipeline executed, result count: {len(results)}")
    if not isinstance(results, list) or not isinstance(results[0], dict):
        print("❌ Error: Invalid result structure")
    return results