import numpy as np
from sklearn.ensemble import IsolationForest
import pickle
import os
import subprocess
import re
from datetime import datetime

class NetworkAnomalyDetector:
    def __init__(self):
        self.model_path = "ml/models/network_model.pkl"
        self.model = None
        self.initialize_model()

    def initialize_model(self):
        """Initialize or load the existing model"""
        if os.path.exists(self.model_path):
            with open(self.model_path, "rb") as f:
                self.model = pickle.load(f)
        else:
            self.model = IsolationForest(contamination=0.05, random_state=42)
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)

    def get_network_features(self):
        """Collect network-related features"""
        features = []
        connection_info = []
        
        try:
            # Get network connections using netstat
            result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True)
            connections = result.stdout.split('\n')
            
            for conn in connections[2:]:  # Skip header lines
                if not conn.strip():
                    continue
                    
                parts = re.split(r'\s+', conn.strip())
                if len(parts) >= 4:
                    local_addr, foreign_addr = parts[3], parts[4]
                    local_port = int(local_addr.split(':')[-1])
                    foreign_port = int(foreign_addr.split(':')[-1])
                    
                    features.append([
                        local_port,
                        foreign_port,
                        len(conn)  # Connection string length as a simple feature
                    ])
                    
                    connection_info.append({
                        'local': local_addr,
                        'foreign': foreign_addr,
                        'state': parts[5] if len(parts) > 5 else 'UNKNOWN'
                    })
                    
        except Exception as e:
            print(f"Error collecting network features: {e}")
            
        return np.array(features), connection_info

    def train_model(self, data):
        """Train the anomaly detection model"""
        if len(data) > 0:
            self.model.fit(data)
            with open(self.model_path, "wb") as f:
                pickle.dump(self.model, f)

    def detect_anomalies(self):
        """Detect anomalous network connections"""
        if self.model is None:
            return [], []
            
        current_data, connection_info = self.get_network_features()
        if len(current_data) == 0:
            return [], []
            
        predictions = self.model.predict(current_data)
        anomalies = []
        
        for i, pred in enumerate(predictions):
            if pred == -1:  # Anomaly detected
                anomalies.append(connection_info[i])
                
        return anomalies, current_data

    def update_model(self, new_data):
        """Update the model with new data"""
        if len(new_data) > 0:
            self.train_model(new_data) 