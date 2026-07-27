import os
import sys
import time
import argparse
import threading
import random
from datetime import datetime

# Initialize colorama for terminal outputs
try:
    from colorama import init, Fore, Style
    init()
except ImportError:
    class Fore:
        RED = "\033[31m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        BLUE = "\033[34m"
        CYAN = "\033[36m"
        WHITE = "\033[37m"
        RESET = "\033[39m"
    class Style:
        BRIGHT = "\033[1m"
        RESET_ALL = "\033[0m"

# ML Libraries for Hybrid Ensemble AI Model
try:
    import pandas as pd
    import numpy as np
    from sklearn.ensemble import IsolationForest, HistGradientBoostingClassifier, RandomForestClassifier
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.neural_network import MLPRegressor
    from sklearn.preprocessing import StandardScaler
    import joblib
except ImportError:
    print(f"{Fore.RED}Error: Required ML libraries not installed.{Fore.RESET}")
    print("Please install requirements using: pip install -r requirements.txt")
    sys.exit(1)

# Try importing Scapy for live sniffing
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    pass

MODEL_PATH = "hybrid_ensemble_model.joblib"
FEATURES = ['packet_count', 'byte_count', 'avg_packet_size', 'unique_dst_ips', 'unique_dst_ports', 'tcp_ratio', 'udp_ratio']

# ==========================================
# 1. Traffic Simulator (for dry-runs/demos)
# ==========================================
def generate_synthetic_data(num_samples=200, label="normal"):
    """
    Generates synthetic network flow data for training/testing.
    """
    data = []
    for _ in range(num_samples):
        if label == "normal":
            device_type = random.choice(["iot", "pc", "tv"])
            if device_type == "iot":
                packet_count = random.randint(2, 10)
                byte_count = packet_count * random.randint(64, 120)
                unique_dst_ips = 1
                unique_dst_ports = 1
                tcp_ratio = 1.0 if random.random() > 0.3 else 0.0
                udp_ratio = 1.0 - tcp_ratio
            elif device_type == "tv":
                packet_count = random.randint(40, 120)
                byte_count = packet_count * random.randint(800, 1400)
                unique_dst_ips = random.randint(1, 2)
                unique_dst_ports = random.randint(1, 2)
                tcp_ratio = random.choice([0.1, 0.9])
                udp_ratio = 1.0 - tcp_ratio
            else:
                packet_count = random.randint(15, 70)
                byte_count = packet_count * random.randint(300, 1100)
                unique_dst_ips = random.randint(2, 6)
                unique_dst_ports = random.randint(2, 8)
                tcp_ratio = random.uniform(0.7, 0.95)
                udp_ratio = 1.0 - tcp_ratio
        elif label == "port_scan":
            packet_count = random.randint(120, 300)
            byte_count = packet_count * random.randint(40, 64)
            unique_dst_ips = 1
            unique_dst_ports = random.randint(40, 120)
            tcp_ratio = 1.0
            udp_ratio = 0.0
        elif label == "ddos":
            packet_count = random.randint(1500, 4000)
            byte_count = packet_count * random.randint(64, 256)
            unique_dst_ips = 1
            unique_dst_ports = 1
            tcp_ratio = 0.0
            udp_ratio = 1.0
        elif label == "data_exfiltration":
            packet_count = random.randint(10, 30)
            byte_count = packet_count * random.randint(15000, 35000)
            unique_dst_ips = 1
            unique_dst_ports = 1
            tcp_ratio = 1.0
            udp_ratio = 0.0
        else:
            raise ValueError("Unknown traffic label")
            
        avg_packet_size = byte_count / packet_count if packet_count > 0 else 0.0
        data.append({
            'packet_count': packet_count,
            'byte_count': byte_count,
            'avg_packet_size': avg_packet_size,
            'unique_dst_ips': unique_dst_ips,
            'unique_dst_ports': unique_dst_ports,
            'tcp_ratio': tcp_ratio,
            'udp_ratio': udp_ratio,
            'label': label
        })
    return pd.DataFrame(data)


# ==========================================
# 2. Live Packet Sniffing & Feature Extraction
# ==========================================
class LiveTrafficMonitor:
    def __init__(self, window_size=10):
        self.window_size = window_size
        self.packets_buffer = []
        self.lock = threading.Lock()
        self.running = False
        
    def packet_callback(self, packet):
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)
        
        proto = "OTHER"
        sport = 0
        dport = 0
        if packet.haslayer(TCP):
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            
        with self.lock:
            self.packets_buffer.append({
                'timestamp': time.time(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'size': size,
                'proto': proto,
                'sport': sport,
                'dport': dport
            })

    def extract_features(self):
        current_time = time.time()
        cutoff_time = current_time - self.window_size
        
        with self.lock:
            window_packets = [p for p in self.packets_buffer if p['timestamp'] >= cutoff_time]
            self.packets_buffer = [p for p in self.packets_buffer if p['timestamp'] >= (current_time - 60)]
            
        if not window_packets:
            return pd.DataFrame()
            
        df_raw = pd.DataFrame(window_packets)
        grouped = df_raw.groupby('src_ip')
        features = []
        
        for src_ip, group in grouped:
            packet_count = len(group)
            byte_count = group['size'].sum()
            unique_dst_ips = group['dst_ip'].nunique()
            
            unique_ports = set(group['sport'].unique()) | set(group['dport'].unique())
            unique_ports.discard(0)
            unique_dst_ports = len(unique_ports) if unique_ports else 1
            
            tcp_count = len(group[group['proto'] == 'TCP'])
            udp_count = len(group[group['proto'] == 'UDP'])
            
            tcp_ratio = tcp_count / packet_count if packet_count > 0 else 0.0
            udp_ratio = udp_count / packet_count if packet_count > 0 else 0.0
            avg_packet_size = byte_count / packet_count if packet_count > 0 else 0.0
            
            features.append({
                'src_ip': src_ip,
                'packet_count': packet_count,
                'byte_count': byte_count,
                'avg_packet_size': avg_packet_size,
                'unique_dst_ips': unique_dst_ips,
                'unique_dst_ports': unique_dst_ports,
                'tcp_ratio': tcp_ratio,
                'udp_ratio': udp_ratio
            })
            
        return pd.DataFrame(features)


# ==========================================
# 3. HYBRID ENSEMBLE AI MODEL
# (Autoencoder + Isolation Forest + GBDT Classifier Fusion)
# ==========================================
class HybridEnsembleDetector:
    def __init__(self, model_path=MODEL_PATH):
        self.model_path = model_path
        self.scaler = StandardScaler()
        # 1. Autoencoder (Unsupervised Reconstruction Error)
        self.autoencoder = MLPRegressor(
            hidden_layer_sizes=(16, 8, 16),
            activation='relu',
            solver='adam',
            max_iter=250,
            random_state=42
        )
        # 2. Isolation Forest (Partitioning Density Outliers)
        self.isolation_forest = IsolationForest(contamination=0.03, random_state=42)
        # 3. Supervised Gradient Boosted Classifier (Multi-class Threat Detector)
        self.classifier = HistGradientBoostingClassifier(random_state=42)
        # Auxiliary models for comparative matrix
        self.rf_classifier = RandomForestClassifier(random_state=42)
        self.dt_classifier = DecisionTreeClassifier(max_depth=3, random_state=42)
        self.mse_baseline_threshold = 1.0

    def train(self, df):
        X = df[FEATURES]
        X_scaled = self.scaler.fit_transform(X)
        
        # 1. Train Autoencoder on normal baseline
        self.autoencoder.fit(X_scaled, X_scaled)
        X_recon = self.autoencoder.predict(X_scaled)
        mse = np.mean(np.square(X_scaled - X_recon), axis=1)
        self.mse_baseline_threshold = float(np.percentile(mse, 95)) + 1e-4
        
        # 2. Train Isolation Forest
        self.isolation_forest.fit(X_scaled)
        
        # 3. Train Multi-class Threat Classifier on synthetic multi-vector dataset
        df_normal = generate_synthetic_data(300, "normal")
        df_scan = generate_synthetic_data(100, "port_scan")
        df_ddos = generate_synthetic_data(100, "ddos")
        df_exfil = generate_synthetic_data(100, "data_exfiltration")
        
        df_all = pd.concat([df_normal, df_scan, df_ddos, df_exfil], ignore_index=True)
        X_all_scaled = self.scaler.transform(df_all[FEATURES])
        y_all = df_all['label']
        
        self.classifier.fit(X_all_scaled, y_all)
        self.rf_classifier.fit(X_all_scaled, y_all)
        self.dt_classifier.fit(X_all_scaled, y_all)
        print(f"{Fore.GREEN}[+] Hybrid Ensemble Model (Autoencoder + IF + GBDT) trained successfully.{Fore.RESET}")
        print(f"{Fore.GREEN}[+] Auxiliary models (Random Forest + Decision Tree) trained successfully.{Fore.RESET}")

    def predict(self, df):
        X = df[FEATURES]
        X_scaled = self.scaler.transform(X)
        
        # 1. Autoencoder Reconstruction Error (MSE)
        X_recon = self.autoencoder.predict(X_scaled)
        mse = np.mean(np.square(X_scaled - X_recon), axis=1)
        mse_scores = np.clip(mse / self.mse_baseline_threshold, 0.0, 2.0)
        
        # 2. Isolation Forest score
        if_raw = self.isolation_forest.decision_function(X_scaled)
        # Convert IF score so higher = more anomalous (0 to 1)
        if_scores = np.clip(0.5 - if_raw, 0.0, 1.0)
        
        # 3. Supervised Threat Classifier prediction & probabilities
        clf_preds = self.classifier.predict(X_scaled)
        clf_probs = self.classifier.predict_proba(X_scaled)
        classes = list(self.classifier.classes_)
        normal_idx = classes.index('normal') if 'normal' in classes else 0
        
        normal_probs = clf_probs[:, normal_idx]
        clf_anomaly_scores = 1.0 - normal_probs
        
        # 4. Hybrid Weighted Fusion Score
        # 40% Autoencoder MSE + 30% Isolation Forest + 30% GBDT Classifier
        fusion_scores = 0.40 * (mse_scores / 2.0) + 0.30 * if_scores + 0.30 * clf_anomaly_scores
        
        # Decision: Anomaly (-1) if Classifier predicts an attack label OR Fusion Score > 0.35
        preds = np.where((clf_preds != 'normal') | (fusion_scores > 0.35), -1, 1)
        
        # Format scores (negative for anomaly in backward-compatible API, lower = worse)
        api_scores = np.where(preds == -1, -fusion_scores, 0.10)
        
        return preds, api_scores, clf_preds, clf_probs

    def predict_comparative(self, df):
        import time
        X = df[FEATURES]
        X_scaled = self.scaler.transform(X)
        n_samples = len(df)
        
        # 1. ENSEMBLE
        t_start = time.perf_counter()
        X_recon = self.autoencoder.predict(X_scaled)
        mse = np.mean(np.square(X_scaled - X_recon), axis=1)
        mse_scores = np.clip(mse / self.mse_baseline_threshold, 0.0, 2.0)
        
        if_raw = self.isolation_forest.decision_function(X_scaled)
        if_scores = np.clip(0.5 - if_raw, 0.0, 1.0)
        
        clf_preds = self.classifier.predict(X_scaled)
        clf_probs = self.classifier.predict_proba(X_scaled)
        classes = list(self.classifier.classes_)
        normal_idx = classes.index('normal') if 'normal' in classes else 0
        
        normal_probs = clf_probs[:, normal_idx]
        clf_anomaly_scores = 1.0 - normal_probs
        
        fusion_scores = 0.40 * (mse_scores / 2.0) + 0.30 * if_scores + 0.30 * clf_anomaly_scores
        ens_preds = np.where((clf_preds != 'normal') | (fusion_scores > 0.35), -1, 1)
        ens_scores = np.where(ens_preds == -1, -fusion_scores, 0.10)
        t_end = time.perf_counter()
        ens_latency = (t_end - t_start) * 1000.0 / n_samples if n_samples > 0 else 0.0
        
        # 2. RANDOM FOREST
        t_start = time.perf_counter()
        rf_preds = self.rf_classifier.predict(X_scaled)
        rf_probs = self.rf_classifier.predict_proba(X_scaled)
        rf_classes = list(self.rf_classifier.classes_)
        rf_normal_idx = rf_classes.index('normal') if 'normal' in rf_classes else 0
        rf_conf = 1.0 - rf_probs[:, rf_normal_idx]
        t_end = time.perf_counter()
        rf_latency = (t_end - t_start) * 1000.0 / n_samples if n_samples > 0 else 0.0
        
        # 3. DECISION TREE
        t_start = time.perf_counter()
        dt_preds = self.dt_classifier.predict(X_scaled)
        dt_probs = self.dt_classifier.predict_proba(X_scaled)
        dt_classes = list(self.dt_classifier.classes_)
        dt_normal_idx = dt_classes.index('normal') if 'normal' in dt_classes else 0
        dt_conf = 1.0 - dt_probs[:, dt_normal_idx]
        t_end = time.perf_counter()
        dt_latency = (t_end - t_start) * 1000.0 / n_samples if n_samples > 0 else 0.0
        
        comparison = []
        for idx in range(n_samples):
            ens_conf = float(fusion_scores[idx]) if ens_preds[idx] == -1 else float(clf_anomaly_scores[idx])
            comparison.append({
                "ensemble": {
                    "label": str(clf_preds[idx]),
                    "confidence": round(ens_conf, 3),
                    "latency_ms": round(ens_latency, 3),
                    "is_anomaly": bool(ens_preds[idx] == -1)
                },
                "random_forest": {
                    "label": str(rf_preds[idx]),
                    "confidence": round(float(rf_conf[idx]), 3),
                    "latency_ms": round(rf_latency, 3),
                    "is_anomaly": bool(rf_preds[idx] != 'normal')
                },
                "decision_tree": {
                    "label": str(dt_preds[idx]),
                    "confidence": round(float(dt_conf[idx]), 3),
                    "latency_ms": round(dt_latency, 3),
                    "is_anomaly": bool(dt_preds[idx] != 'normal')
                }
            })
            
        return ens_preds, ens_scores, clf_preds, clf_probs, comparison

    def save(self):
        joblib.dump({
            'scaler': self.scaler,
            'autoencoder': self.autoencoder,
            'isolation_forest': self.isolation_forest,
            'classifier': self.classifier,
            'rf_classifier': getattr(self, 'rf_classifier', RandomForestClassifier(random_state=42)),
            'dt_classifier': getattr(self, 'dt_classifier', DecisionTreeClassifier(max_depth=3, random_state=42)),
            'mse_threshold': self.mse_baseline_threshold
        }, self.model_path)
        print(f"{Fore.GREEN}[+] Saved Hybrid Ensemble Model to {self.model_path}{Fore.RESET}")

    def load(self):
        if os.path.exists(self.model_path):
            data = joblib.load(self.model_path)
            self.scaler = data['scaler']
            self.autoencoder = data['autoencoder']
            self.isolation_forest = data['isolation_forest']
            self.classifier = data['classifier']
            self.rf_classifier = data.get('rf_classifier', RandomForestClassifier(random_state=42))
            self.dt_classifier = data.get('dt_classifier', DecisionTreeClassifier(max_depth=3, random_state=42))
            self.mse_baseline_threshold = data.get('mse_threshold', 1.0)
            print(f"{Fore.GREEN}[+] Loaded Hybrid Ensemble Model from {self.model_path}{Fore.RESET}")
            return True
        else:
            print(f"{Fore.YELLOW}[!] Model file {self.model_path} not found. Creating & training initial model...{Fore.RESET}")
            initial_df = generate_synthetic_data(250, "normal")
            self.train(initial_df)
            self.save()
            return True


# Backward compatibility alias
AnomalyDetector = HybridEnsembleDetector


# ==========================================
# 4. Command Line Execution & Simulation
# ==========================================
def run_simulation():
    print(f"\n{Style.BRIGHT}{Fore.CYAN}=================================================={Fore.RESET}")
    print(f"   HYBRID ENSEMBLE AI SECURITY SIMULATION (v3.0)  ")
    print(f"=================================================={Style.RESET_ALL}\n")
    
    print("[1] Training Hybrid Ensemble Model (Autoencoder + IF + GBDT)...")
    detector = HybridEnsembleDetector()
    normal_df = generate_synthetic_data(250, "normal")
    detector.train(normal_df)
    detector.save()
    
    print("\n[2] Simulating live traffic streams with cyber attacks...")
    test_df = pd.concat([
        generate_synthetic_data(15, "normal"),
        generate_synthetic_data(3, "port_scan"),
        generate_synthetic_data(3, "ddos"),
        generate_synthetic_data(3, "data_exfiltration")
    ], ignore_index=True).sample(frac=1).reset_index(drop=True)
    
    preds, scores, clf_labels, clf_probs = detector.predict(test_df)
    
    print(f"\n{Style.BRIGHT}{'SOURCE IP':<15} | {'PACKETS':<7} | {'BYTES':<10} | {'CLASSIFICATION':<18} | {'SCORE':<7} | {'DETECTION':<18}{Style.RESET_ALL}")
    print("-" * 80)
    
    for i, row in test_df.iterrows():
        src_ip = f"192.168.1.{random.randint(10, 50)}" if row['label'] == 'normal' else f"192.168.1.{random.randint(200, 220)} (ATTACK)"
        pred = preds[i]
        score = scores[i]
        label = clf_labels[i]
        
        if pred == -1:
            alert_msg = f"{Fore.RED}[ALERT] HYBRID ANOMALY ({label.upper()}){Fore.RESET}"
            print(f"{Fore.YELLOW}{src_ip:<15} | {int(row['packet_count']):<7} | {int(row['byte_count']):<10} | {label:<18} | {score:+.3f} | {alert_msg}")
        else:
            print(f"{Fore.GREEN}{src_ip:<15} | {int(row['packet_count']):<7} | {int(row['byte_count']):<10} | {label:<18} | {score:+.3f} | Normal{Fore.RESET}")
            
        time.sleep(0.3)

def run_detect():
    print(f"\n{Style.BRIGHT}{Fore.CYAN}=================================================={Fore.RESET}")
    print(f"   LIVE HYBRID ENSEMBLE AI TRAFFIC MONITORING      ")
    print(f"=================================================={Style.RESET_ALL}\n")
    
    if not SCAPY_AVAILABLE:
        print(f"{Fore.RED}[!] Scapy is not available. Please install Npcap/Scapy to run live packet sniffing.{Fore.RESET}")
        return

    detector = HybridEnsembleDetector()
    if not detector.load():
        print("[*] Training initial model baseline...")
        normal_df = generate_synthetic_data(250, "normal")
        detector.train(normal_df)
        detector.save()
        
    monitor = LiveTrafficMonitor(window_size=10)
    print(f"{Fore.GREEN}[+] Starting live packet capture on network interfaces...{Fore.RESET}")
    print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop.{Fore.RESET}\n")
    
    sniff_thread = threading.Thread(target=lambda: sniff(prn=monitor.packet_callback, store=0), daemon=True)
    sniff_thread.start()
    
    print(f"{Style.BRIGHT}{'TIME':<8} | {'SOURCE IP':<15} | {'PACKETS':<7} | {'BYTES':<8} | {'PORTS':<5} | {'SCORE':<7} | {'STATUS'}{Style.RESET_ALL}")
    print("-" * 80)
    
    try:
        while True:
            time.sleep(5)
            features_df = monitor.extract_features()
            if features_df.empty:
                continue
                
            preds, scores, clf_labels, clf_probs = detector.predict(features_df)
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            for idx, row in features_df.iterrows():
                src_ip = row['src_ip']
                pkts = int(row['packet_count'])
                bytes_cnt = int(row['byte_count'])
                ports = int(row['unique_dst_ports'])
                score = scores[idx]
                is_anomaly = (preds[idx] == -1)
                label = clf_labels[idx]
                
                if is_anomaly:
                    status_str = f"{Fore.RED}[ALERT] ANOMALY ({label.upper()}){Fore.RESET}"
                    print(f"{timestamp:<8} | {Fore.YELLOW}{src_ip:<15}{Fore.RESET} | {pkts:<7} | {bytes_cnt:<8} | {ports:<5} | {score:+.3f} | {status_str}")
                else:
                    status_str = f"{Fore.GREEN}Normal{Fore.RESET}"
                    print(f"{timestamp:<8} | {src_ip:<15} | {pkts:<7} | {bytes_cnt:<8} | {ports:<5} | {score:+.3f} | {status_str}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Live monitoring stopped by user.{Fore.RESET}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hybrid Ensemble AI Network Anomaly Detector")
    parser.add_argument("--mode", choices=["simulate", "detect", "sniff", "train"], default="simulate")
    args = parser.parse_args()
    
    if args.mode in ["detect", "sniff"]:
        run_detect()
    elif args.mode == "train":
        detector = HybridEnsembleDetector()
        normal_df = generate_synthetic_data(300, "normal")
        detector.train(normal_df)
        detector.save()
    else:
        run_simulation()
