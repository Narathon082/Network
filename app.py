import os
import sys
import time
import threading
import random
import pandas as pd
from datetime import datetime
from flask import Flask, jsonify, render_template, request

# Import existing logic from traffic_monitor
from traffic_monitor import AnomalyDetector, LiveTrafficMonitor, generate_synthetic_data, SCAPY_AVAILABLE, FEATURES

app = Flask(__name__)

# Thread-safe global variables
state_lock = threading.Lock()
current_mode = "simulate"  # "simulate", "train", "detect"
detection_enabled = True   # Start/Stop toggle flag
detector = AnomalyDetector()
detector_loaded = detector.load()  # Try to load existing model
live_monitor = None
live_sniffer_thread = None

# Flow history database in memory
latest_flows = []
alerts_log = []
system_status = "System Idle"
training_progress = 0  # percentage 0-100

def background_monitor_worker():
    global system_status, latest_flows, alerts_log, current_mode, training_progress, detector_loaded, detection_enabled
    print("[+] Background monitor thread started.")
    
    # In-memory buffer of training data if in train mode
    training_data_buffer = []
    training_start_time = None
    training_duration = 30  # seconds for GUI demo training
    
    # Simple simulator loop state
    sim_tick = 0
    
    while True:
        try:
            time.sleep(2)  # Update UI every 2 seconds
            
            with state_lock:
                mode = current_mode
                enabled = detection_enabled
                
            if not enabled:
                system_status = "Monitoring Paused (Idle)"
                with state_lock:
                    latest_flows = []
                continue
                
            if mode == "simulate":
                sim_tick += 1
                system_status = "Monitoring (Simulation Mode)"
                
                # Normal flows (from 3-6 devices)
                normal_df = generate_synthetic_data(random.randint(3, 6), "normal")
                attack_df = pd.DataFrame()
                
                # Every 4 ticks, inject a random attack
                if sim_tick % 4 == 0:
                    attack_type = random.choice(["port_scan", "ddos", "data_exfiltration"])
                    attack_df = generate_synthetic_data(1, attack_type)
                
                tick_df = pd.concat([normal_df, attack_df], ignore_index=True)
                tick_df = tick_df.sample(frac=1).reset_index(drop=True)
                
                # Convert DataFrame to a list of dicts with Mock IPs
                flows_list = []
                for idx, row in tick_df.iterrows():
                    is_attack = row['label'] != 'normal'
                    if is_attack:
                        ip = f"192.168.1.{random.randint(200, 220)}"
                    else:
                        # Fixed IPs for standard home devices to make charts look consistent
                        ip_choices = ["192.168.1.15 (Smart TV)", "192.168.1.24 (My Laptop)", "192.168.1.10 (IP Camera)", "192.168.1.37 (Smart Plug)"]
                        ip = ip_choices[idx % len(ip_choices)]
                        
                    flows_list.append({
                        'ip': ip,
                        'packet_count': int(row['packet_count']),
                        'byte_count': int(row['byte_count']),
                        'avg_packet_size': round(float(row['avg_packet_size']), 2),
                        'unique_dst_ips': int(row['unique_dst_ips']),
                        'unique_dst_ports': int(row['unique_dst_ports']),
                        'tcp_ratio': round(float(row['tcp_ratio']), 2),
                        'udp_ratio': round(float(row['udp_ratio']), 2),
                        'true_label': row['label']
                    })
                
                # Run AI Prediction
                if detector_loaded:
                    temp_df = pd.DataFrame(flows_list)
                    preds, scores = detector.predict(temp_df)
                    
                    for i, flow in enumerate(flows_list):
                        flow['score'] = round(float(scores[i]), 3)
                        flow['is_anomaly'] = int(preds[i]) == -1
                        
                        if flow['is_anomaly'] and flow['true_label'] != 'normal':
                            # Log real attack alert
                            alert = {
                                'timestamp': datetime.now().strftime("%H:%M:%S"),
                                'ip': flow['ip'],
                                'type': flow['true_label'].upper(),
                                'score': flow['score'],
                                'details': f"Packets: {flow['packet_count']}, Bytes: {flow['byte_count']}, Avg Size: {flow['avg_packet_size']} B"
                            }
                            # Check if alert already logged recently to prevent duplicates
                            if not any(a['ip'] == alert['ip'] and a['type'] == alert['type'] for a in alerts_log[:3]):
                                alerts_log.insert(0, alert)
                        elif flow['is_anomaly'] and flow['true_label'] == 'normal':
                            # False alarm
                            alert = {
                                'timestamp': datetime.now().strftime("%H:%M:%S"),
                                'ip': flow['ip'],
                                'type': "FALSE ALARM (NORMAL)",
                                'score': flow['score'],
                                'details': f"Packets: {flow['packet_count']}, Bytes: {flow['byte_count']}, Avg Size: {flow['avg_packet_size']} B"
                            }
                            if not any(a['ip'] == alert['ip'] and a['type'] == alert['type'] for a in alerts_log[:3]):
                                alerts_log.insert(0, alert)
                else:
                    for flow in flows_list:
                        flow['score'] = 0.0
                        flow['is_anomaly'] = False
                        
                with state_lock:
                    latest_flows = flows_list
                    if len(alerts_log) > 30:
                        alerts_log = alerts_log[:30]
                    
            elif mode == "train":
                if not training_start_time:
                    training_start_time = time.time()
                    training_data_buffer = []
                    system_status = "AI Model Training in Progress..."
                    
                elapsed = time.time() - training_start_time
                progress = min(100, int((elapsed / training_duration) * 100))
                
                with state_lock:
                    training_progress = progress
                
                if SCAPY_AVAILABLE and live_monitor:
                    df_features = live_monitor.extract_features()
                    if not df_features.empty:
                        training_data_buffer.append(df_features)
                else:
                    # Simulate training baseline ingestion
                    mock_train = generate_synthetic_data(15, "normal")
                    training_data_buffer.append(mock_train)
                    
                if elapsed >= training_duration:
                    if training_data_buffer:
                        all_train_df = pd.concat(training_data_buffer, ignore_index=True)
                        detector.train(all_train_df)
                        detector.save()
                        detector_loaded = True
                    
                    with state_lock:
                        current_mode = "detect"
                        training_progress = 0
                        system_status = "Monitoring (Live Mode)"
                    training_start_time = None
                    print("[+] Training completed and saved model.")
                    
            elif mode == "detect":
                system_status = "Monitoring (Live Mode)"
                flows_list = []
                
                if SCAPY_AVAILABLE and live_monitor:
                    df_features = live_monitor.extract_features()
                    if not df_features.empty:
                        if detector_loaded:
                            preds, scores = detector.predict(df_features)
                            for idx, row in df_features.iterrows():
                                score = float(scores[idx])
                                is_anomaly = int(preds[idx]) == -1
                                flow = {
                                    'ip': row['src_ip'],
                                    'packet_count': int(row['packet_count']),
                                    'byte_count': int(row['byte_count']),
                                    'avg_packet_size': round(float(row['avg_packet_size']), 2),
                                    'unique_dst_ips': int(row['unique_dst_ips']),
                                    'unique_dst_ports': int(row['unique_dst_ports']),
                                    'tcp_ratio': round(float(row['tcp_ratio']), 2),
                                    'udp_ratio': round(float(row['udp_ratio']), 2),
                                    'score': round(score, 3),
                                    'is_anomaly': is_anomaly
                                }
                                flows_list.append(flow)
                                
                                if is_anomaly:
                                    alert = {
                                        'timestamp': datetime.now().strftime("%H:%M:%S"),
                                        'ip': flow['ip'],
                                        'type': "SUSPICIOUS BEHAVIOR",
                                        'score': flow['score'],
                                        'details': f"Packets: {flow['packet_count']}, Bytes: {flow['byte_count']}, Avg Size: {flow['avg_packet_size']} B"
                                    }
                                    if not any(a['ip'] == alert['ip'] and a['timestamp'] == alert['timestamp'] for a in alerts_log[:3]):
                                        alerts_log.insert(0, alert)
                        else:
                            for idx, row in df_features.iterrows():
                                flows_list.append({
                                    'ip': row['src_ip'],
                                    'packet_count': int(row['packet_count']),
                                    'byte_count': int(row['byte_count']),
                                    'avg_packet_size': round(float(row['avg_packet_size']), 2),
                                    'unique_dst_ips': int(row['unique_dst_ips']),
                                    'unique_dst_ports': int(row['unique_dst_ports']),
                                    'tcp_ratio': round(float(row['tcp_ratio']), 2),
                                    'udp_ratio': round(float(row['udp_ratio']), 2),
                                    'score': 0.0,
                                    'is_anomaly': False
                                })
                else:
                    # Sniffer not available or driver missing: simulate normal live traffic
                    system_status = "Monitoring (Live Mode - No Sniffer Driver)"
                    normal_df = generate_synthetic_data(random.randint(2, 4), "normal")
                    flows_list = []
                    for idx, row in normal_df.iterrows():
                        ip_choices = ["192.168.1.15 (Smart TV)", "192.168.1.24 (My Laptop)", "192.168.1.10 (IP Camera)"]
                        ip = ip_choices[idx % len(ip_choices)]
                        flows_list.append({
                            'ip': ip,
                            'packet_count': int(row['packet_count']),
                            'byte_count': int(row['byte_count']),
                            'avg_packet_size': round(float(row['avg_packet_size']), 2),
                            'unique_dst_ips': int(row['unique_dst_ips']),
                            'unique_dst_ports': int(row['unique_dst_ports']),
                            'tcp_ratio': round(float(row['tcp_ratio']), 2),
                            'udp_ratio': round(float(row['udp_ratio']), 2),
                            'score': 0.0,
                            'is_anomaly': False
                        })
                        
                with state_lock:
                    latest_flows = flows_list
                    if len(alerts_log) > 30:
                        alerts_log = alerts_log[:30]
                    
        except Exception as e:
            print(f"Error in background worker: {e}")
            time.sleep(2)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    global current_mode, detector_loaded, system_status, training_progress, detection_enabled
    with state_lock:
        return jsonify({
            'mode': current_mode,
            'model_loaded': detector_loaded,
            'status_message': system_status,
            'training_progress': training_progress,
            'scapy_available': SCAPY_AVAILABLE,
            'detection_enabled': detection_enabled
        })

@app.route('/api/flows')
def get_flows():
    with state_lock:
        return jsonify({
            'flows': latest_flows,
            'alerts': alerts_log
        })

@app.route('/api/action', methods=['POST'])
def trigger_action():
    global current_mode, live_monitor, live_sniffer_thread, detection_enabled
    data = request.json or {}
    action = data.get('action')
    
    if action == 'set_mode':
        new_mode = data.get('mode')
        if new_mode in ['simulate', 'train', 'detect']:
            with state_lock:
                current_mode = new_mode
                
            if new_mode in ['train', 'detect'] and SCAPY_AVAILABLE:
                if not live_monitor:
                    live_monitor = LiveTrafficMonitor(window_size=10)
                    def run_sniff():
                        from scapy.all import sniff
                        try:
                            sniff(prn=live_monitor.packet_callback, store=False)
                        except Exception as e:
                            print(f"[!] Scapy sniffing failed: {e}")
                    live_sniffer_thread = threading.Thread(target=run_sniff, daemon=True)
                    live_sniffer_thread.start()
                    
            return jsonify({'status': 'success', 'mode': new_mode})
        return jsonify({'status': 'error', 'message': 'Invalid mode'}), 400
        
    elif action == 'toggle_detection':
        with state_lock:
            detection_enabled = not detection_enabled
            new_state = detection_enabled
        return jsonify({'status': 'success', 'detection_enabled': new_state})
        
    elif action == 'clear_alerts':
        global alerts_log
        with state_lock:
            alerts_log = []
        return jsonify({'status': 'success'})
        
    return jsonify({'status': 'error', 'message': 'Unknown action'}), 400

if __name__ == '__main__':
    # Start the background sniffer/simulator worker thread
    t = threading.Thread(target=background_monitor_worker, daemon=True)
    t.start()
    
    print("[+] Starting Web GUI on http://127.0.0.1:5000")
    # Disable flask reloader to avoid running background thread twice
    app.run(host='127.0.0.1', port=5000, debug=False)
