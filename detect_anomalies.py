import pandas as pd
from sklearn.preprocessing import StandardScaler
from pyod.models.iforest import IForest
import os
from datetime import datetime

OUTPUT_PATH = "output/flagged_users.csv"

def run_detection(input_file):
    df = pd.read_csv(input_file, encoding='utf-8-sig')
    required_cols = ['user_id', 'files_accessed', 'usb_inserted', 'data_transferred_MB']
    missing = [col for col in required_cols if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    features = ['files_accessed', 'usb_inserted', 'data_transferred_MB']
    X = df[features]
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    if X_scaled.shape[0] < 5:
        raise ValueError("Dataset too small for anomaly detection.")

    model = IForest()
    model.fit(X_scaled)
    df['anomaly_score'] = model.decision_function(X_scaled)
    df['is_anomaly'] = model.predict(X_scaled)

    os.makedirs("output", exist_ok=True)
    df.to_csv(OUTPUT_PATH, index=False)
    log_file = f"output/flagged_users_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    df.to_csv(log_file, index=False)
    print("✅ Detection complete.")
