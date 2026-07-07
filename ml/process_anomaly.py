import psutil
import numpy as np
from sklearn.ensemble import IsolationForest
import pickle
import os
from datetime import datetime

class ProcessAnomalyDetector:
    def __init__(self):
        self.model_path = "ml/models/process_model.pkl"
        self.model = None
        self.initialize_model()

    def initialize_model(self):
        """Initialize or load the existing model"""
        if os.path.exists(self.model_path):
            with open(self.model_path, "rb") as f:
                self.model = pickle.load(f)
        else:
            self.model = IsolationForest(contamination=0.05, random_state=42)
            # Create models directory if it doesn't exist
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)

    def get_process_features(self):
        """Collect process-related features"""
        features = []
        process_info = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'create_time']):
            try:
                proc_info = proc.info
                features.append([
                    proc_info['cpu_percent'],
                    proc_info['memory_percent'],
                    (datetime.now().timestamp() - proc_info['create_time']) / 3600  # Process age in hours
                ])
                process_info.append({
                    'pid': proc_info['pid'],
                    'name': proc_info['name']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return np.array(features), process_info

    def train_model(self, data):
        """Train the anomaly detection model"""
        self.model.fit(data)
        with open(self.model_path, "wb") as f:
            pickle.dump(self.model, f)

    def detect_anomalies(self):
        """Detect anomalous processes"""
        if self.model is None:
            return [], []
            
        current_data, process_info = self.get_process_features()
        if len(current_data) == 0:
            return [], []
            
        predictions = self.model.predict(current_data)
        anomalies = []
        
        for i, pred in enumerate(predictions):
            if pred == -1:  # Anomaly detected
                anomalies.append(process_info[i])
                
        return anomalies, current_data

    def update_model(self, new_data):
        """Update the model with new data"""
        if len(new_data) > 0:
            self.train_model(new_data) 