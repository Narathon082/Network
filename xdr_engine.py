import time
import random
import threading
import subprocess
import os
from datetime import datetime

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

class XDRStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.incidents = []
        self.telemetry = {
            'network': [],
            'endpoint': [],
            'identity': []
        }
        self.quarantined_hosts = set()  # set of IPs/Hostnames
        self.blocked_ips = set()         # set of malicious remote IPs
        self.terminated_pids = set()     # set of killed process IDs
        self.whitelisted_ips = set()     # set of whitelisted IPs
        self.soar_enabled = True         # Automated response enabled by default
        self.real_execution_enabled = False # Toggle between Simulation and Live OS Execution
        self.response_logs = []          # Execution audit log
        self.stats = {
            'total_incidents': 0,
            'threats_mitigated': 0,
            'active_quarantines': 0,
            'auto_actions_taken': 0
        }

class XDREngine:
    def __init__(self):
        self.store = XDRStore()
        # Pre-seed baseline endpoints
        self.endpoints = [
            {'ip': '192.168.1.15', 'hostname': 'WORKSTATION-TV-01', 'user': 'system_iot', 'os': 'Linux IoT'},
            {'ip': '192.168.1.24', 'hostname': 'DEV-LAPTOP-WIN11', 'user': 'alex_dev', 'os': 'Windows 11 Enterprise'},
            {'ip': '192.168.1.10', 'hostname': 'SECURITY-CAM-01', 'user': 'cam_admin', 'os': 'Embedded Linux'},
            {'ip': '192.168.1.37', 'hostname': 'SMART-PLUG-HQ', 'user': 'iot_hub', 'os': 'FreeRTOS'},
            {'ip': '192.168.1.210', 'hostname': 'UNKNOWN-HOST-X', 'user': 'guest_user', 'os': 'Unknown'}
        ]

    def log_response_action(self, action_type, target, status, trigger="Manual SOC Action", details=""):
        log_entry = {
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'action': action_type,
            'target': target,
            'status': status,
            'trigger': trigger,
            'details': details
        }
        with self.store.lock:
            self.store.response_logs.insert(0, log_entry)
            if len(self.store.response_logs) > 50:
                self.store.response_logs = self.store.response_logs[:50]

    def set_real_execution_mode(self, enabled):
        with self.store.lock:
            self.store.real_execution_enabled = enabled
        mode_str = "LIVE OS EXECUTION MODE" if enabled else "SIMULATION MODE (DRY-RUN)"
        self.log_response_action(
            action_type="EXECUTION_MODE_CHANGE",
            target="XDR SOAR Engine",
            status=mode_str,
            trigger="Manual SOC Toggle",
            details=f"XDR Engine switched to {mode_str}."
        )

    def isolate_host(self, ip_or_hostname, trigger="Manual SOC Action"):
        with self.store.lock:
            self.store.quarantined_hosts.add(ip_or_hostname)
            self.store.stats['active_quarantines'] = len(self.store.quarantined_hosts)
            self.store.stats['threats_mitigated'] += 1
            is_live = self.store.real_execution_enabled

        details_msg = f"Network interfaces for {ip_or_hostname} severed by XDR Containment."
        if is_live:
            try:
                # Add real Windows Firewall block rules
                cmd_in = f'netsh advfirewall firewall add rule name="XDR_ISOLATE_{ip_or_hostname}" dir=in action=block remoteip={ip_or_hostname}'
                cmd_out = f'netsh advfirewall firewall add rule name="XDR_ISOLATE_{ip_or_hostname}" dir=out action=block remoteip={ip_or_hostname}'
                subprocess.run(cmd_in, shell=True, capture_output=True, text=True)
                subprocess.run(cmd_out, shell=True, capture_output=True, text=True)
                details_msg = f"[LIVE OS] Windows Firewall rules added blocking all traffic for {ip_or_hostname}."
            except Exception as e:
                details_msg = f"[LIVE OS ERROR] Failed to execute firewall isolation: {e}"

        self.log_response_action(
            action_type="ISOLATE_HOST",
            target=ip_or_hostname,
            status="SUCCESS (LIVE OS CONTAINED)" if is_live else "SUCCESS (HOST CONTAINED)",
            trigger=trigger,
            details=details_msg
        )

    def release_host(self, ip_or_hostname):
        with self.store.lock:
            self.store.quarantined_hosts.discard(ip_or_hostname)
            self.store.stats['active_quarantines'] = len(self.store.quarantined_hosts)
            is_live = self.store.real_execution_enabled

        details_msg = f"Network access restored for {ip_or_hostname}."
        if is_live:
            try:
                cmd_del = f'netsh advfirewall firewall delete rule name="XDR_ISOLATE_{ip_or_hostname}"'
                subprocess.run(cmd_del, shell=True, capture_output=True, text=True)
                details_msg = f"[LIVE OS] Windows Firewall isolation rules for {ip_or_hostname} deleted."
            except Exception as e:
                details_msg = f"[LIVE OS ERROR] Failed to delete firewall rule: {e}"

        self.log_response_action(
            action_type="RELEASE_HOST",
            target=ip_or_hostname,
            status="SUCCESS (LIVE OS RESTORED)" if is_live else "SUCCESS (RESTORED)",
            trigger="Manual SOC Action",
            details=details_msg
        )

    def block_ip(self, ip_address, trigger="Manual SOC Action"):
        with self.store.lock:
            self.store.blocked_ips.add(ip_address)
            self.store.stats['threats_mitigated'] += 1
            is_live = self.store.real_execution_enabled

        details_msg = f"Inbound/Outbound traffic for IP {ip_address} blocked on firewall."
        if is_live:
            try:
                cmd_in = f'netsh advfirewall firewall add rule name="XDR_BLOCK_{ip_address}" dir=in action=block remoteip={ip_address}'
                cmd_out = f'netsh advfirewall firewall add rule name="XDR_BLOCK_{ip_address}" dir=out action=block remoteip={ip_address}'
                subprocess.run(cmd_in, shell=True, capture_output=True, text=True)
                subprocess.run(cmd_out, shell=True, capture_output=True, text=True)
                details_msg = f"[LIVE OS] Firewall rule injected blocking IP {ip_address}."
            except Exception as e:
                details_msg = f"[LIVE OS ERROR] Failed to block IP on firewall: {e}"

        self.log_response_action(
            action_type="BLOCK_IP",
            target=ip_address,
            status="SUCCESS (LIVE FIREWALL RULE ADDED)" if is_live else "SUCCESS (FIREWALL RULE ADDED)",
            trigger=trigger,
            details=details_msg
        )

    def unblock_ip(self, ip_address):
        with self.store.lock:
            self.store.blocked_ips.discard(ip_address)
            is_live = self.store.real_execution_enabled

        details_msg = f"Firewall block rule for IP {ip_address} removed."
        if is_live:
            try:
                cmd_del = f'netsh advfirewall firewall delete rule name="XDR_BLOCK_{ip_address}"'
                subprocess.run(cmd_del, shell=True, capture_output=True, text=True)
                details_msg = f"[LIVE OS] Firewall block rule for IP {ip_address} removed."
            except Exception as e:
                details_msg = f"[LIVE OS ERROR] Failed to remove firewall rule: {e}"

        self.log_response_action(
            action_type="UNBLOCK_IP",
            target=ip_address,
            status="SUCCESS (RULE REMOVED)",
            trigger="Manual SOC Action",
            details=details_msg
        )

    def kill_process(self, pid, process_name="", trigger="Manual SOC Action"):
        with self.store.lock:
            self.store.terminated_pids.add(str(pid))
            self.store.stats['threats_mitigated'] += 1
            is_live = self.store.real_execution_enabled

        details_msg = f"Malicious process tree PID {pid} forcefully terminated by XDR Agent."
        status_str = "SUCCESS (PROCESS TERMINATED)"

        if is_live:
            try:
                if PSUTIL_AVAILABLE:
                    try:
                        p = psutil.Process(int(pid))
                        proc_n = p.name()
                        p.kill()
                        details_msg = f"[LIVE OS] Real OS Process {proc_n} (PID {pid}) forcefully killed via psutil."
                        status_str = "SUCCESS (REAL PROCESS KILLED)"
                    except psutil.NoSuchProcess:
                        details_msg = f"[LIVE OS] Process PID {pid} was no longer running."
                        status_str = "PROCESS ALREADY TERMINATED"
                else:
                    res = subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True)
                    if res.returncode == 0:
                        details_msg = f"[LIVE OS] Taskkill output: {res.stdout.strip()}"
                        status_str = "SUCCESS (REAL PROCESS KILLED)"
                    else:
                        details_msg = f"[LIVE OS] Taskkill failed: {res.stderr.strip()}"
            except Exception as e:
                details_msg = f"[LIVE OS ERROR] Exception during taskkill PID {pid}: {e}"

        self.log_response_action(
            action_type="KILL_PROCESS",
            target=f"PID {pid} ({process_name})",
            status=status_str,
            trigger=trigger,
            details=details_msg
        )

    def set_soar_mode(self, enabled):
        with self.store.lock:
            self.store.soar_enabled = enabled
        self.log_response_action(
            action_type="SOAR_CONFIG",
            target="XDR Automation Engine",
            status="ENABLED" if enabled else "DISABLED",
            trigger="Manual SOC Action",
            details=f"SOAR Auto-Response set to {'ENABLED' if enabled else 'DISABLED'}."
        )

    def whitelist_ip(self, ip_address):
        with self.store.lock:
            self.store.whitelisted_ips.add(ip_address)
            self.store.quarantined_hosts.discard(ip_address)
            self.store.blocked_ips.discard(ip_address)
        self.log_response_action(
            action_type="WHITELIST_IP",
            target=ip_address,
            status="SUCCESS (ADDED TO WHITELIST)",
            trigger="Manual SOC Action",
            details=f"IP {ip_address} added to whitelist. Future alerts ignored."
        )

    def unwhitelist_ip(self, ip_address):
        with self.store.lock:
            self.store.whitelisted_ips.discard(ip_address)
        self.log_response_action(
            action_type="UNWHITELIST_IP",
            target=ip_address,
            status="SUCCESS (REMOVED FROM WHITELIST)",
            trigger="Manual SOC Action",
            details=f"IP {ip_address} removed from whitelist."
        )

    def generate_endpoint_telemetry(self):
        """Generates real or simulated endpoint telemetry"""
        with self.store.lock:
            is_live = self.store.real_execution_enabled

        if is_live and PSUTIL_AVAILABLE:
            try:
                # Capture actual running processes on Windows host
                proc_list = []
                for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        p_info = p.info
                        if p_info['name']:
                            proc_list.append(p_info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                if proc_list:
                    p_sample = random.choice(proc_list[:40])
                    cpu_val = round(p_sample.get('cpu_percent') or 0.0, 1)
                    mem_val = round(p_sample.get('memory_percent') or 0.0, 1)
                    
                    return {
                        'timestamp': datetime.now().strftime("%H:%M:%S"),
                        'vector': 'ENDPOINT (REAL OS)',
                        'host': os.getenv('COMPUTERNAME', 'LOCAL-HOST'),
                        'ip': '127.0.0.1',
                        'process_name': p_sample['name'],
                        'pid': p_sample['pid'],
                        'cpu': f"{cpu_val}%",
                        'mem': f"{mem_val}%",
                        'is_anomaly': False,
                        'anomaly_type': 'Real OS Process',
                        'details': f"[REAL OS PROCESS] {p_sample['name']} (PID: {p_sample['pid']}) CPU: {cpu_val}%, Mem: {mem_val}%"
                    }
            except Exception as e:
                print(f"[!] Real endpoint telemetry error: {e}")

        # Synthetic fallback
        processes = [
            {'name': 'svchost.exe', 'pid': 1042, 'status': 'NORMAL', 'cpu': '1.2%', 'mem': '24MB'},
            {'name': 'chrome.exe', 'pid': 4380, 'status': 'NORMAL', 'cpu': '5.4%', 'mem': '310MB'},
            {'name': 'python.exe', 'pid': 8920, 'status': 'NORMAL', 'cpu': '2.1%', 'mem': '85MB'},
            {'name': 'nc.exe (Netcat)', 'pid': 6664, 'status': 'SUSPICIOUS', 'cpu': '48.9%', 'mem': '12MB', 'anomaly': True, 'type': 'Reverse Shell Spawn'},
            {'name': 'powershell.exe', 'pid': 9912, 'status': 'SUSPICIOUS', 'cpu': '82.0%', 'mem': '150MB', 'anomaly': True, 'type': 'Encoded Command Execution'},
            {'name': 'mimikatz.exe', 'pid': 3133, 'status': 'CRITICAL', 'cpu': '95.0%', 'mem': '45MB', 'anomaly': True, 'type': 'LSASS Memory Dump Attempt'}
        ]
        
        endpoint_event = random.choice(processes)
        device = random.choice(self.endpoints)
        
        return {
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'vector': 'ENDPOINT',
            'host': device['hostname'],
            'ip': device['ip'],
            'process_name': endpoint_event['name'],
            'pid': endpoint_event['pid'],
            'cpu': endpoint_event['cpu'],
            'mem': endpoint_event['mem'],
            'is_anomaly': endpoint_event.get('anomaly', False),
            'anomaly_type': endpoint_event.get('type', 'Normal Exec'),
            'details': f"Process {endpoint_event['name']} (PID: {endpoint_event['pid']}) CPU: {endpoint_event['cpu']}, Mem: {endpoint_event['mem']}"
        }

    def generate_identity_telemetry(self):
        """Simulates identity and access management logs"""
        identity_events = [
            {'user': 'alex_dev', 'event': 'User Login Success', 'status': 'NORMAL', 'auth_type': 'Kerberos/MFA'},
            {'user': 'cam_admin', 'event': 'API Token Authenticated', 'status': 'NORMAL', 'auth_type': 'Bearer Token'},
            {'user': 'root_admin', 'event': 'SSH Brute-Force Spike', 'status': 'SUSPICIOUS', 'auth_type': 'Password', 'anomaly': True, 'type': 'Brute Force Attempt'},
            {'user': 'guest_user', 'event': 'Privilege Escalation Attempt', 'status': 'CRITICAL', 'auth_type': 'SUDO/Token Abuse', 'anomaly': True, 'type': 'Privilege Escalation'},
            {'user': 'unknown_actor', 'event': 'Impossible Travel Login (US -> CN)', 'status': 'SUSPICIOUS', 'auth_type': 'OAuth SSO', 'anomaly': True, 'type': 'Credential Theft'}
        ]
        
        event = random.choice(identity_events)
        device = random.choice(self.endpoints)
        
        return {
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'vector': 'IDENTITY',
            'user': event['user'],
            'ip': device['ip'],
            'event': event['event'],
            'auth_type': event['auth_type'],
            'is_anomaly': event.get('anomaly', False),
            'anomaly_type': event.get('type', 'Normal Auth'),
            'details': f"User '{event['user']}' triggered '{event['event']}' via {event['auth_type']}"
        }

    def ingest_and_correlate(self, network_flows, network_alerts):
        ep_event = self.generate_endpoint_telemetry()
        id_event = self.generate_identity_telemetry()
        
        with self.store.lock:
            self.store.telemetry['endpoint'].insert(0, ep_event)
            if len(self.store.telemetry['endpoint']) > 30:
                self.store.telemetry['endpoint'] = self.store.telemetry['endpoint'][:30]
                
            self.store.telemetry['identity'].insert(0, id_event)
            if len(self.store.telemetry['identity']) > 30:
                self.store.telemetry['identity'] = self.store.telemetry['identity'][:30]

            self.store.telemetry['network'] = network_flows[:30] if network_flows else []

        new_incidents = []
        
        for alert in network_alerts[:5]:
            ip = alert['ip']
            alert_type = alert.get('type', 'NETWORK_ANOMALY')
            score = alert.get('score', 0.0)
            
            if ip in self.store.whitelisted_ips or ip in self.store.quarantined_hosts or ip in self.store.blocked_ips:
                continue
                
            if "DDOS" in alert_type or "DATA_EXFILTRATION" in alert_type or score < -0.05:
                severity = "CRITICAL"
                threat_score = 92
            elif "PORT_SCAN" in alert_type:
                severity = "HIGH"
                threat_score = 78
            else:
                severity = "MEDIUM"
                threat_score = 65
                
            matching_ep = [e for e in self.store.telemetry['endpoint'] if e['ip'] == ip and e['is_anomaly']]
            matching_id = [i for i in self.store.telemetry['identity'] if i['ip'] == ip and i['is_anomaly']]
            
            vectors = ['Network']
            ep_details = "No abnormal host process detected."
            if matching_ep:
                vectors.append('Endpoint')
                ep_details = f"Correlated with Malicious Process: {matching_ep[0]['process_name']} (PID: {matching_ep[0]['pid']})"
            
            if matching_id:
                vectors.append('Identity')
                
            incident_id = f"XDR-INC-{random.randint(1000, 9999)}"
            
            already_logged = any(inc['ip'] == ip and inc['status'] == 'ACTIVE' for inc in self.store.incidents[:5])
            if not already_logged:
                incident = {
                    'id': incident_id,
                    'timestamp': alert['timestamp'],
                    'ip': ip,
                    'title': f"{alert_type} Detected on {ip}",
                    'severity': severity,
                    'threat_score': threat_score,
                    'vectors': vectors,
                    'status': 'ACTIVE',
                    'root_cause': f"AI score {score} flagged payload anomaly. {ep_details}",
                    'raw_details': alert['details'],
                    'playbook': "SOAR Containment: Isolate Host & Block Malicious Socket",
                    'mitigated': False
                }
                new_incidents.append(incident)
                
                if self.store.soar_enabled and severity in ["CRITICAL", "HIGH"]:
                    self.isolate_host(ip, trigger=f"SOAR Auto-Playbook ({incident_id})")
                    self.block_ip(ip, trigger=f"SOAR Auto-Playbook ({incident_id})")
                    incident['status'] = 'CONTAINED'
                    incident['mitigated'] = True
                    self.store.stats['auto_actions_taken'] += 1

        if ep_event['is_anomaly'] and ep_event['pid'] not in self.store.terminated_pids:
            if ep_event['process_name'] in ['mimikatz.exe', 'nc.exe (Netcat)']:
                incident_id = f"XDR-INC-{random.randint(1000, 9999)}"
                already_logged = any(inc['raw_details'].find(str(ep_event['pid'])) != -1 for inc in self.store.incidents[:5])
                if not already_logged:
                    incident = {
                        'id': incident_id,
                        'timestamp': ep_event['timestamp'],
                        'ip': ep_event['ip'],
                        'title': f"Endpoint Malicious Execution: {ep_event['process_name']}",
                        'severity': 'CRITICAL',
                        'threat_score': 95,
                        'vectors': ['Endpoint'],
                        'status': 'ACTIVE',
                        'root_cause': f"Suspicious host execution: {ep_event['anomaly_type']}",
                        'raw_details': ep_event['details'],
                        'playbook': "SOAR Process Kill & Host Quarantine",
                        'mitigated': False
                    }
                    new_incidents.append(incident)
                    
                    if self.store.soar_enabled:
                        self.kill_process(ep_event['pid'], ep_event['process_name'], trigger=f"SOAR Auto-Playbook ({incident_id})")
                        incident['status'] = 'CONTAINED'
                        incident['mitigated'] = True
                        self.store.stats['auto_actions_taken'] += 1

        with self.store.lock:
            for inc in new_incidents:
                self.store.incidents.insert(0, inc)
                self.store.stats['total_incidents'] += 1
            if len(self.store.incidents) > 40:
                self.store.incidents = self.store.incidents[:40]

    def get_dashboard_data(self):
        with self.store.lock:
            return {
                'incidents': self.store.incidents,
                'telemetry': self.store.telemetry,
                'quarantined_hosts': list(self.store.quarantined_hosts),
                'blocked_ips': list(self.store.blocked_ips),
                'terminated_pids': list(self.store.terminated_pids),
                'whitelisted_ips': list(self.store.whitelisted_ips),
                'soar_enabled': self.store.soar_enabled,
                'real_execution_enabled': self.store.real_execution_enabled,
                'response_logs': self.store.response_logs,
                'stats': {
                    'total_incidents': self.store.stats['total_incidents'],
                    'threats_mitigated': self.store.stats['threats_mitigated'],
                    'active_quarantines': len(self.store.quarantined_hosts),
                    'active_blocked_ips': len(self.store.blocked_ips),
                    'auto_actions_taken': self.store.stats['auto_actions_taken']
                }
            }
