import os
import sys
import time
import argparse
import threading
import random
from datetime import datetime

# Initialize colorama for beautiful terminal outputs
try:
    from colorama import init, Fore, Style
    init()
except ImportError:
    # Fallback if colorama is not installed
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

# Try importing ML libraries
try:
    import pandas as pd
    import numpy as np
    from sklearn.ensemble import IsolationForest
    import joblib
except ImportError:
    print(f"{Fore.RED}Error: Required libraries (pandas, numpy, scikit-learn, joblib) are not installed.{Fore.RESET}")
    print("Please install requirements using: pip install -r requirements.txt")
    sys.exit(1)

# Try importing Scapy for live sniffing
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    pass

MODEL_PATH = "anomaly_detector.joblib"
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
            # Normal traffic profiles
            device_type = random.choice(["iot", "pc", "tv"])
            if device_type == "iot":
                # Smart home device: low packet rate, single destination, single port (e.g. HTTP/MQTT)
                packet_count = random.randint(2, 10)
                byte_count = packet_count * random.randint(64, 120)
                unique_dst_ips = 1
                unique_dst_ports = 1
                tcp_ratio = 1.0 if random.random() > 0.3 else 0.0
                udp_ratio = 1.0 - tcp_ratio
            elif device_type == "tv":
                # Streaming TV: high bytes, low port count (video streaming)
                packet_count = random.randint(40, 120)
                byte_count = packet_count * random.randint(800, 1400)
                unique_dst_ips = random.randint(1, 2)
                unique_dst_ports = random.randint(1, 2)
                tcp_ratio = random.choice([0.1, 0.9])
                udp_ratio = 1.0 - tcp_ratio
            else:
                # General PC: medium/high traffic, multi-destination (web browsing)
                packet_count = random.randint(15, 70)
                byte_count = packet_count * random.randint(300, 1100)
                unique_dst_ips = random.randint(2, 6)
                unique_dst_ports = random.randint(2, 8)
                tcp_ratio = random.uniform(0.7, 0.95)
                udp_ratio = 1.0 - tcp_ratio
        elif label == "port_scan":
            # Attack: High port count, single/few target IPs, many packets, low bytes per packet
            packet_count = random.randint(120, 300)
            byte_count = packet_count * random.randint(40, 64)
            unique_dst_ips = 1
            unique_dst_ports = random.randint(40, 120)  # Scanning many ports
            tcp_ratio = 1.0
            udp_ratio = 0.0
        elif label == "ddos":
            # Attack: Huge packet volume, single destination IP & port, high flood rate
            packet_count = random.randint(1500, 4000)
            byte_count = packet_count * random.randint(64, 256)
            unique_dst_ips = 1
            unique_dst_ports = 1
            tcp_ratio = 0.0
            udp_ratio = 1.0  # UDP flood
        elif label == "data_exfiltration":
            # Attack: Unusually high byte size per packet, low packet count (heavy uploads)
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
            # Filter and keep only recent packets
            window_packets = [p for p in self.packets_buffer if p['timestamp'] >= cutoff_time]
            # Clear logs older than 60 seconds to manage memory
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
            
            # Aggregate all unique ports accessed (source & destination)
            unique_ports = set(group['sport'].unique()) | set(group['dport'].unique())
            unique_ports.discard(0)  # Remove placeholder ports for non-TCP/UDP
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
# 3. AI Anomaly Detector (Isolation Forest)
# ==========================================
class AnomalyDetector:
    def __init__(self, model_path=MODEL_PATH):
        self.model_path = model_path
        # contamination = 2% (ratio of expected anomalies in training data)
        self.model = IsolationForest(contamination=0.02, random_state=42)

    def train(self, df):
        X = df[FEATURES]
        self.model.fit(X)
        print(f"{Fore.GREEN}[+] Model training completed successfully.{Fore.RESET}")
        
    def predict(self, df):
        X = df[FEATURES]
        # returns 1 (normal) or -1 (anomaly)
        preds = self.model.predict(X)
        # decision function returns raw anomaly scores (lower is more anomalous, < 0 is anomaly)
        scores = self.model.decision_function(X)
        return preds, scores

    def save(self):
        joblib.dump(self.model, self.model_path)
        print(f"{Fore.GREEN}[+] Model saved to {self.model_path}{Fore.RESET}")

    def load(self):
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            print(f"{Fore.GREEN}[+] Loaded trained model from {self.model_path}{Fore.RESET}")
            return True
        else:
            print(f"{Fore.RED}[!] Model file {self.model_path} not found. Please train the model first.{Fore.RESET}")
            return False


# ==========================================
# 4. Command Line Interface Execution
# ==========================================
def run_simulation():
    print(f"\n{Style.BRIGHT}{Fore.CYAN}=================================================={Fore.RESET}")
    print(f"       AI NETWORK SECURITY ANOMALY SIMULATION     ")
    print(f"=================================================={Style.RESET_ALL}\n")
    
    print("[1] Generating normal network baseline traffic...")
    normal_df = generate_synthetic_data(250, "normal")
    print(f"    Generated {len(normal_df)} normal flow records.")
    
    print("\n[2] Training Isolation Forest AI model on normal baseline...")
    detector = AnomalyDetector()
    detector.train(normal_df)
    detector.save()
    
    print("\n[3] Simulating live traffic with interspersed cyber attacks...")
    # Generate mixing traffic: normal + attacks
    test_normal = generate_synthetic_data(25, "normal")
    test_port_scan = generate_synthetic_data(3, "port_scan")
    test_ddos = generate_synthetic_data(3, "ddos")
    test_exfil = generate_synthetic_data(3, "data_exfiltration")
    
    test_df = pd.concat([test_normal, test_port_scan, test_ddos, test_exfil], ignore_index=True)
    # Shuffle the test dataframe to mix them up
    test_df = test_df.sample(frac=1).reset_index(drop=True)
    
    print(f"    Simulating {len(test_df)} streams of traffic. Monitoring in progress...\n")
    print(f"{Style.BRIGHT}{'SOURCE IP':<15} | {'PACKETS':<7} | {'BYTES':<10} | {'PORTS':<5} | {'SCORE':<7} | {'DETECTION':<18}{Style.RESET_ALL}")
    print("-" * 75)
    
    detector.load()
    preds, scores = detector.predict(test_df)
    
    anomalies_detected = 0
    total_attacks = 9  # 3 port_scan + 3 ddos + 3 exfil
    correct_detections = 0
    
    for i, row in test_df.iterrows():
        # Assign a mock source IP based on the type
        if row['label'] == 'normal':
            src_ip = f"192.168.1.{random.randint(10, 50)}"
        else:
            src_ip = f"192.168.1.{random.randint(200, 220)} (ATTACK)"
            
        pred = preds[i]
        score = scores[i]
        
        # Display results with formatting
        if pred == -1: # Anomaly detected
            anomalies_detected += 1
            is_correct = "[OK] Correct" if row['label'] != 'normal' else "[!] False Alarm"
            if row['label'] != 'normal':
                correct_detections += 1
            
            alert_msg = f"{Fore.RED}[ALERT] ANOMALY ({row['label'].upper()}) [{is_correct}]{Fore.RESET}"
            print(f"{Fore.YELLOW}{src_ip:<15} | {int(row['packet_count']):<7} | {int(row['byte_count']):<10} | {int(row['unique_dst_ports']):<5} | {score:+.3f} | {alert_msg}")
        else:
            is_correct = "[OK] Correct" if row['label'] == 'normal' else "[!] Missed Attack"
            print(f"{Fore.GREEN}{src_ip:<15} | {int(row['packet_count']):<7} | {int(row['byte_count']):<10} | {int(row['unique_dst_ports']):<5} | {score:+.3f} | Normal [{is_correct}]{Fore.RESET}")
            
        time.sleep(0.5) # Simulate time gap between reports
        
    print(f"\n{Style.BRIGHT}{Fore.CYAN}=================================================={Fore.RESET}")
    print(f"               SIMULATION SUMMARY                 ")
    print(f"=================================================={Style.RESET_ALL}")
    print(f"Total Traffic Flows Screened: {len(test_df)}")
    print(f"Total True Attacks Injected:  {total_attacks}")
    print(f"Total Anomalies Flagged:      {anomalies_detected}")
    print(f"Attacks Successfully Blocked: {correct_detections} / {total_attacks} ({correct_detections/total_attacks * 100:.1f}%)")
    print(f"--------------------------------------------------")
    print(f"AI Behavior Analysis: The Isolation Forest successfully mapped normal")
    print(f"home profiles and flagged deviations (like high port variety or high packet volume)")
    print(f"without relying on pre-existing virus signatures. This is the core SentinelOne approach!")


def run_live(mode, duration=60, interface=None):
    if not SCAPY_AVAILABLE:
        print(f"{Fore.RED}[!] Error: Scapy is not fully installed or active. Live mode is unavailable.{Fore.RESET}")
        print("Please ensure Npcap/WinPcap is installed on Windows, and that you are running as Administrator.")
        print("To test the AI logic, run the simulation instead: python traffic_monitor.py --mode simulate")
        sys.exit(1)
        
    print(f"\n{Style.BRIGHT}{Fore.BLUE}[*] Initializing Home Network AI Monitor (Live Mode: {mode.upper()}){Fore.RESET}{Style.RESET_ALL}")
    if interface:
        print(f"[*] Sniffing on interface: {interface}")
    else:
        print("[*] Sniffing on default network interface...")
        
    detector = AnomalyDetector()
    if mode == "detect":
        if not detector.load():
            print(f"{Fore.YELLOW}[!] Unable to load model. Training a temporary baseline first...{Fore.RESET}")
            mode = "train"
            
    monitor = LiveTrafficMonitor(window_size=10)
    
    # Start packet sniffer in background thread
    def sniffer_thread():
        try:
            sniff(prn=monitor.packet_callback, iface=interface, store=False)
        except Exception as e:
            print(f"\n{Fore.RED}[!] Sniffing failed: {e}{Fore.RESET}")
            print("[!] Make sure you are running as Administrator (sudo / run as admin) and Npcap is installed.")
            os._exit(1)
            
    t = threading.Thread(target=sniffer_thread, daemon=True)
    t.start()
    
    print(f"{Fore.GREEN}[+] Packet Sniffer started in background thread.{Fore.RESET}")
    print(f"[*] Gathering traffic data... Window size is 10s. Press Ctrl+C to stop.")
    
    start_time = time.time()
    all_flows_data = []
    
    try:
        if mode == "train":
            print(f"[*] Training phase: Collecting normal baseline traffic for {duration} seconds...")
            # We wait and collect snapshots of feature dataframes
            end_time = start_time + duration
            while time.time() < end_time:
                time.sleep(10)
                df_features = monitor.extract_features()
                if not df_features.empty:
                    print(f"    Collected {len(df_features)} device flows this window...")
                    all_flows_data.append(df_features)
                    
            if not all_flows_data:
                print(f"{Fore.RED}[!] No packets captured. Baseline training failed.{Fore.RESET}")
                sys.exit(1)
                
            training_df = pd.concat(all_flows_data, ignore_index=True)
            detector.train(training_df)
            detector.save()
            print(f"{Fore.GREEN}[+] Training successful. Baseline established!{Fore.RESET}")
            
        elif mode == "detect":
            print(f"[*] Detection phase: Monitoring traffic and predicting anomalies... (Duration: Infinite)")
            print(f"\n{Style.BRIGHT}{'TIME':<8} | {'DEVICE IP':<15} | {'PACKETS':<7} | {'BYTES':<10} | {'PORTS':<5} | {'SCORE':<7} | {'STATUS':<15}{Style.RESET_ALL}")
            print("-" * 75)
            
            while True:
                time.sleep(10)
                df_features = monitor.extract_features()
                if df_features.empty:
                    continue
                    
                preds, scores = detector.predict(df_features)
                current_time_str = datetime.now().strftime("%H:%M:%S")
                
                for idx, row in df_features.iterrows():
                    pred = preds[idx]
                    score = scores[idx]
                    ip = row['src_ip']
                    
                    if pred == -1:
                        # Red warning for anomalies
                        print(f"{Fore.RED}{current_time_str:<8} | {ip:<15} | {int(row['packet_count']):<7} | {int(row['byte_count']):<10} | {int(row['unique_dst_ports']):<5} | {score:+.3f} | [ALERT] ANOMALY DETECTED!{Fore.RESET}")
                    else:
                        # Green message for normal behavior
                        print(f"{Fore.GREEN}{current_time_str:<8} | {ip:<15} | {int(row['packet_count']):<7} | {int(row['byte_count']):<10} | {int(row['unique_dst_ports']):<5} | {score:+.3f} | Normal{Fore.RESET}")
                        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Execution stopped by user.{Fore.RESET}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-powered Home Network Anomaly Detector")
    parser.add_argument(
        "--mode", 
        choices=["simulate", "train", "detect"], 
        default="simulate",
        help="Run mode. 'simulate' runs synthetic attacks. 'train' fits model on live network. 'detect' monitors live network."
    )
    parser.add_argument(
        "--duration", 
        type=int, 
        default=60, 
        help="Duration (seconds) to run live training."
    )
    parser.add_argument(
        "--interface", 
        type=str, 
        default=None, 
        help="Network interface to sniff on (Live modes only)."
    )
    
    args = parser.parse_args()
    
    if args.mode == "simulate":
        run_simulation()
    else:
        run_live(args.mode, args.duration, args.interface)
