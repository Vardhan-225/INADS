# flask_detection/config.py

import os

# Dataset and Model Paths
BASE_DIR = "/Users/akashthanneeru/Desktop/INADS_Data/Models/Final"
DATA_PATH = "/Users/akashthanneeru/Desktop/INADS_Data/Data/Indexed_Dataset_Cyclical_Encoded.csv"

GLOBAL_MODEL = os.path.join(BASE_DIR, "Global", "xgb_global_model.pkl")
EDGE_MODEL = os.path.join(BASE_DIR, "Edge", "LSTM", "edge_layer_lstm_best.keras")
DEVICE_MODEL = os.path.join(BASE_DIR, "Device", "device_layer_mlp_model.h5")

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

# Database Credentials
MYSQL_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "Catsanddogs#666",
    "database": "INADS"
}