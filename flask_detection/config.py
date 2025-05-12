# flask_detection/config.py

import os

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR   = os.getenv("MODEL_BASE_DIR", "Models")
DATA_PATH  = os.getenv("DATA_PATH", "data/Indexed_Dataset_Cyclical_Encoded.csv")

GLOBAL_MODEL_PATH = os.path.join(BASE_DIR, "Global", "xgb_global_model.pkl")
EDGE_MODEL_PATH   = os.path.join(BASE_DIR, "Edge", "LSTM", "edge_layer_lstm_best.keras")
DEVICE_MODEL_PATH = os.path.join(BASE_DIR, "Device", "device_layer_mlp_model.h5")

OUTPUT_CSV    = os.path.join(BASE_DIR, "core_layer_results.csv")
RESULTS_DIR   = BASE_DIR

# ─── Feature Lists ───────────────────────────────────────────────────────────
GLOBAL_FEATURES = [
    "Flow Duration", "Flow Byts/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Dst Port", "Protocol", "SYN Flag Cnt", "ACK Flag Cnt", "FIN Flag Cnt", "PSH Flag Cnt",
    "Pkt Len Min", "Pkt Len Max", "Fwd Pkts/s", "Bwd Pkts/s",
    "Fwd Pkt Len Max", "Bwd Pkt Len Min", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Hour_sin", "Hour_cos", "Weekday_sin", "Weekday_cos"
]
EDGE_FEATURES = [
    "Pkt Len Min", "Pkt Len Max", "Fwd Pkt Len Max", "Bwd Pkt Len Min",
    "Fwd Pkts/s", "Bwd Pkts/s", "Fwd IAT Mean"
]
DEVICE_FEATURES = [
    "Dst Port", "Fwd Pkt Len Max", "Bwd Pkt Len Min", "Pkt Len Var",
    "Fwd Pkt Len Std", "Bwd Pkt Len Std", "Flow Duration",
    "Flow IAT Mean", "Flow IAT Std", "Idle Max", "Idle Mean",
    "Active Min", "Active Max", "Init Fwd Win Byts", "Init Bwd Win Byts",
    "Fwd Header Len", "Bwd Header Len", "Pkt Size Avg",
    "Fwd Seg Size Avg", "Bwd Seg Size Avg", "Hour_sin", "Hour_cos"
]

# ─── Fusion Weights & Threshold ───────────────────────────────────────────────
W_GLOBAL  = 0.3
W_EDGE    = 0.3
W_DEVICE  = 0.4
THRESHOLD = 0.5

# ─── Batch / Sleep Settings ─────────────────────────────────────────────────
BATCH_INSERT_SIZE  = int(os.getenv("BATCH_SIZE", "10000"))
SLEEP_INTERVAL_SEC = float(os.getenv("SLEEP_SEC", "0.1"))

# ─── MySQL ────────────────────────────────────────────────────────────────────
MYSQL_CONFIG = {
    "host":     os.getenv("MYSQL_HOST",     "localhost"),
    "user":     os.getenv("MYSQL_USER",     "root"),
    "password": os.getenv("MYSQL_PASSWORD", "Catsanddogs#666"),
    "database": os.getenv("MYSQL_DB",       "INADS"),
}