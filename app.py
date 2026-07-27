import os
import sys
import time
import threading
import random
import pandas as pd
from datetime import datetime
from flask import Flask, jsonify, render_template, request

# Import existing logic from traffic_monitor and xdr_engine
from traffic_monitor import AnomalyDetector, LiveTrafficMonitor, generate_synthetic_data, SCAPY_AVAILABLE, FEATURES
from xdr_engine import XDREngine
import aivss_engine
from wazuh_manager import WazuhManager
wazuh_mgr = WazuhManager()

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

# Thread-safe global variables
state_lock = threading.Lock()
current_mode = "simulate"  # "simulate", "train", "detect"
detection_enabled = True   # Start/Stop toggle flag
detector = AnomalyDetector()
detector_loaded = detector.load()  # Try to load existing model
live_monitor = None
live_sniffer_thread = None
active_classifier_model = "ensemble"  # "ensemble", "random_forest", "decision_tree"

# Initialize XDR Engine
xdr_engine = XDREngine()

# Flow history database in memory
latest_flows = []
alerts_log = []
system_status = "System Idle"
training_progress = 0  # percentage 0-100

def background_monitor_worker():
    global system_status, latest_flows, alerts_log, current_mode, training_progress, detector_loaded, detection_enabled
    print("[+] Background monitor thread started.")
    
    training_data_buffer = []
    training_start_time = None
    training_duration = 30  # seconds for GUI demo training
    
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
                system_status = "Monitoring (Simulation Mode - XDR Active)"
                
                # Normal flows (from 3-6 devices)
                normal_df = generate_synthetic_data(random.randint(3, 6), "normal")
                attack_df = pd.DataFrame()
                
                # Every 3 ticks, inject a random attack
                if sim_tick % 3 == 0:
                    attack_type = random.choice(["port_scan", "ddos", "data_exfiltration"])
                    attack_df = generate_synthetic_data(1, attack_type)
                
                tick_df = pd.concat([normal_df, attack_df], ignore_index=True)
                tick_df = tick_df.sample(frac=1).reset_index(drop=True)
                
                flows_list = []
                for idx, row in tick_df.iterrows():
                    is_attack = row['label'] != 'normal'
                    if is_attack:
                        ip = f"192.168.1.{random.randint(200, 220)}"
                    else:
                        ip_choices = ["192.168.1.15", "192.168.1.24", "192.168.1.10", "192.168.1.37"]
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
                
                # Run Hybrid Ensemble AI Prediction
                if detector_loaded:
                    temp_df = pd.DataFrame(flows_list)
                    preds, scores, clf_preds, clf_probs, comparison = detector.predict_comparative(temp_df)

                    for i, flow in enumerate(flows_list):
                        flow['score'] = round(float(scores[i]), 3)
                        flow['is_anomaly'] = int(preds[i]) == -1
                        flow['clf_label'] = str(clf_preds[i])
                        flow['comparison'] = comparison[i]
                        
                        # Switch behavior based on active model select
                        if active_classifier_model == "random_forest":
                            flow['is_anomaly'] = comparison[i]['random_forest']['is_anomaly']
                            flow['clf_label'] = comparison[i]['random_forest']['label']
                            flow['score'] = -comparison[i]['random_forest']['confidence'] if flow['is_anomaly'] else 0.10
                        elif active_classifier_model == "decision_tree":
                            flow['is_anomaly'] = comparison[i]['decision_tree']['is_anomaly']
                            flow['clf_label'] = comparison[i]['decision_tree']['label']
                            flow['score'] = -comparison[i]['decision_tree']['confidence'] if flow['is_anomaly'] else 0.10
                        
                        if flow['is_anomaly']:
                            attack_type = flow['clf_label'].upper() if flow['clf_label'] != 'normal' else "HYBRID ANOMALY"
                            alert = {
                                'timestamp': datetime.now().strftime("%H:%M:%S"),
                                'ip': flow['ip'],
                                'type': attack_type,
                                'score': flow['score'],
                                'details': f"Active Model Score: {abs(flow['score']):.3f} | Packets: {flow['packet_count']}, Bytes: {flow['byte_count']}, Avg Size: {flow['avg_packet_size']} B"
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

                # Pass to XDR Engine for Correlation & SOAR Automation
                xdr_engine.ingest_and_correlate(latest_flows, alerts_log)
                    
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
                        system_status = "Monitoring (Live Mode - XDR Active)"
                    training_start_time = None
                    print("[+] Training completed and saved model.")
                    
            elif mode == "detect":
                system_status = "Monitoring (Live Mode - XDR Active)"
                flows_list = []
                
                if SCAPY_AVAILABLE and live_monitor:
                    df_features = live_monitor.extract_features()
                    if not df_features.empty:
                        if detector_loaded:
                            preds, scores, clf_preds, clf_probs, comparison = detector.predict_comparative(df_features)
                                
                            for idx, row in df_features.iterrows():
                                score = float(scores[idx])
                                is_anomaly = int(preds[idx]) == -1
                                clf_label = str(clf_preds[idx])
                                comp_details = comparison[idx]
                                
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
                                    'is_anomaly': is_anomaly,
                                    'clf_label': clf_label,
                                    'comparison': comp_details
                                }
                                
                                # Switch behavior based on active model select
                                if active_classifier_model == "random_forest":
                                    flow['is_anomaly'] = comp_details['random_forest']['is_anomaly']
                                    flow['clf_label'] = comp_details['random_forest']['label']
                                    flow['score'] = -comp_details['random_forest']['confidence'] if flow['is_anomaly'] else 0.10
                                elif active_classifier_model == "decision_tree":
                                    flow['is_anomaly'] = comp_details['decision_tree']['is_anomaly']
                                    flow['clf_label'] = comp_details['decision_tree']['label']
                                    flow['score'] = -comp_details['decision_tree']['confidence'] if flow['is_anomaly'] else 0.10
                                
                                flows_list.append(flow)
                                
                                if flow['is_anomaly']:
                                    attack_type = flow['clf_label'].upper() if flow['clf_label'] != 'normal' else "SUSPICIOUS BEHAVIOR"
                                    alert = {
                                        'timestamp': datetime.now().strftime("%H:%M:%S"),
                                        'ip': flow['ip'],
                                        'type': attack_type,
                                        'score': flow['score'],
                                        'details': f"Active Model Score: {abs(flow['score']):.3f} | Packets: {flow['packet_count']}, Bytes: {flow['byte_count']}, Avg Size: {flow['avg_packet_size']} B"
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
                    system_status = "Monitoring (Live Mode - No Sniffer Driver)"
                    normal_df = generate_synthetic_data(random.randint(2, 4), "normal")
                    flows_list = []
                    for idx, row in normal_df.iterrows():
                        ip_choices = ["192.168.1.15", "192.168.1.24", "192.168.1.10"]
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

                xdr_engine.ingest_and_correlate(latest_flows, alerts_log)

                # Evaluate Wazuh XML rules against new telemetry
                # 1. Match network flows
                for flow in latest_flows:
                    wazuh_mgr.match_telemetry('network', flow)
                    
                # 2. Match latest endpoint telemetry
                if xdr_engine.store.telemetry['endpoint']:
                    latest_ep = xdr_engine.store.telemetry['endpoint'][0]
                    cpu_cleaned = 0.0
                    try:
                        cpu_cleaned = float(latest_ep['cpu'].replace('%', ''))
                    except Exception:
                        pass
                    wazuh_mgr.match_telemetry('endpoint', {
                        'ip': latest_ep['ip'],
                        'host': latest_ep['host'],
                        'process_name': latest_ep['process_name'],
                        'pid': latest_ep['pid'],
                        'cpu': cpu_cleaned,
                        'mem': latest_ep['mem']
                    })
                    
                # 3. Match latest identity logs
                if xdr_engine.store.telemetry['identity']:
                    latest_id = xdr_engine.store.telemetry['identity'][0]
                    wazuh_mgr.match_telemetry('identity', {
                        'ip': latest_id['ip'],
                        'user': latest_id['user'],
                        'event': latest_id['event'],
                        'auth_type': latest_id['auth_type']
                    })
                    
        except Exception as e:
            print(f"Error in background worker: {e}")
            time.sleep(2)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    global current_mode, detector_loaded, system_status, training_progress, detection_enabled, active_classifier_model
    with state_lock:
        return jsonify({
            'mode': current_mode,
            'model_loaded': detector_loaded,
            'status_message': system_status,
            'training_progress': training_progress,
            'scapy_available': SCAPY_AVAILABLE,
            'detection_enabled': detection_enabled,
            'active_model': active_classifier_model
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

# ==================== AIVSS & MODEL SANDBOX API ROUTES ====================
@app.route('/api/aivss/config')
def get_aivss_config():
    return jsonify({
        "industries": aivss_engine.INDUSTRIES,
        "av_options": aivss_engine.AV_OPTIONS,
        "ac_options": aivss_engine.AC_OPTIONS,
        "pr_options": aivss_engine.PR_OPTIONS,
        "ui_options": aivss_engine.UI_OPTIONS,
        "s_options": aivss_engine.S_OPTIONS,
        "model_complexity_options": aivss_engine.MODEL_COMPLEXITY_OPTIONS,
        "severity_options": aivss_engine.SEVERITY_OPTIONS,
        "impact_options": aivss_engine.IMPACT_OPTIONS,
        "exploitability_options": aivss_engine.EXPLOITABILITY_OPTIONS,
        "remediation_level_options": aivss_engine.REMEDIATION_LEVEL_OPTIONS,
        "report_confidence_options": aivss_engine.REPORT_CONFIDENCE_OPTIONS,
        "env_req_options": aivss_engine.ENV_REQ_OPTIONS,
        "env_multiplier_options": aivss_engine.ENV_MULTIPLIER_OPTIONS,
        "ai_subcategories": aivss_engine.AI_SUBCATEGORIES,
        "presets": aivss_engine.PRESETS
    })

@app.route('/api/aivss/calculate', methods=['POST'])
def calculate_aivss_score():
    data = request.json or {}
    result = aivss_engine.calculate_aivss_score_logic(data)
    return jsonify(result)

@app.route('/api/model/active', methods=['GET', 'POST'])
def get_or_set_active_model():
    global active_classifier_model
    if request.method == 'POST':
        data = request.json or {}
        model_name = data.get('model')
        if model_name in ['ensemble', 'random_forest', 'decision_tree']:
            with state_lock:
                active_classifier_model = model_name
            return jsonify({'status': 'success', 'active_model': active_classifier_model})
        return jsonify({'status': 'error', 'message': 'Invalid model name'}), 400
    else:
        with state_lock:
            return jsonify({'active_model': active_classifier_model})

# ==================== XDR API ROUTES ====================
@app.route('/api/xdr/data')
def get_xdr_data():
    return jsonify(xdr_engine.get_dashboard_data())

@app.route('/api/xdr/response', methods=['POST'])
def trigger_xdr_response():
    data = request.json or {}
    action = data.get('action')
    target = data.get('target')
    
    if not action or not target:
        return jsonify({'status': 'error', 'message': 'Missing action or target'}), 400
        
    if action == 'isolate_host':
        xdr_engine.isolate_host(target, trigger="SOC Manual Action")
    elif action == 'release_host':
        xdr_engine.release_host(target)
    elif action == 'block_ip':
        xdr_engine.block_ip(target, trigger="SOC Manual Action")
    elif action == 'unblock_ip':
        xdr_engine.unblock_ip(target)
    elif action == 'kill_process':
        pid = data.get('pid', target)
        process_name = data.get('process_name', '')
        xdr_engine.kill_process(pid, process_name, trigger="SOC Manual Action")
    elif action == 'whitelist_ip':
        xdr_engine.whitelist_ip(target)
    elif action == 'unwhitelist_ip':
        xdr_engine.unwhitelist_ip(target)
    else:
        return jsonify({'status': 'error', 'message': 'Unknown action'}), 400
        
    return jsonify({'status': 'success', 'data': xdr_engine.get_dashboard_data()})

@app.route('/api/xdr/config', methods=['POST'])
def update_xdr_config():
    data = request.json or {}
    soar_enabled = data.get('soar_enabled')
    real_execution_enabled = data.get('real_execution_enabled')
    
    if soar_enabled is not None:
        xdr_engine.set_soar_mode(bool(soar_enabled))
    if real_execution_enabled is not None:
        xdr_engine.set_real_execution_mode(bool(real_execution_enabled))
        
    return jsonify({
        'status': 'success',
        'soar_enabled': xdr_engine.store.soar_enabled,
        'real_execution_enabled': xdr_engine.store.real_execution_enabled
    })

@app.route('/api/xdr/clear_incidents', methods=['POST'])
def clear_xdr_incidents():
    xdr_engine.clear_all()
    return jsonify({'status': 'success'})

# ==================== WAZUH SIEM API ROUTES ====================
@app.route('/api/wazuh/status')
def get_wazuh_status():
    agents_dict = [a.to_dict() for a in wazuh_mgr.agents.values()]
    alerts_dict = [a.to_dict() for a in wazuh_mgr.alerts]
    return jsonify({
        'agents': agents_dict,
        'alerts': alerts_dict,
        'active_response_logs': wazuh_mgr.active_response_logs,
        'rules_xml': wazuh_mgr.get_rules_xml_string()
    })

@app.route('/api/wazuh/action', methods=['POST'])
def trigger_wazuh_action():
    data = request.json or {}
    agent_id = data.get('agent_id')
    action = data.get('action')
    
    if not agent_id or not action:
        return jsonify({'status': 'error', 'message': 'Missing agent_id or action'}), 400
        
    success, msg = wazuh_mgr.trigger_agent_response(agent_id, action)
    if success:
        return jsonify({'status': 'success', 'message': msg})
    return jsonify({'status': 'error', 'message': msg}), 400

@app.route('/api/wazuh/rules/save', methods=['POST'])
def save_wazuh_rules():
    data = request.json or {}
    xml_string = data.get('rules_xml')
    if not xml_string:
        return jsonify({'status': 'error', 'message': 'Missing rules_xml'}), 400
        
    success, msg = wazuh_mgr.save_rules_xml_string(xml_string)
    if success:
        return jsonify({'status': 'success', 'message': msg})
    return jsonify({'status': 'error', 'message': msg}), 400

if __name__ == '__main__':
    t = threading.Thread(target=background_monitor_worker, daemon=True)
    t.start()
    
    print("[+] Starting XDR Web GUI on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=False)
