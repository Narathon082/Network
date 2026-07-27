import xml.etree.ElementTree as ET
import uuid
import datetime
import threading
import time

class WazuhAgent:
    def __init__(self, agent_id, hostname, ip, os_name, status="active"):
        self.id = agent_id
        self.hostname = hostname
        self.ip = ip
        self.os = os_name
        self.status = status  # active, disconnected
        self.fim_status = "idle"  # idle, scanning, completed
        self.vulnerabilities_count = len(hostname) % 3  # simulated vulnerabilities

    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'ip': self.ip,
            'os': self.os,
            'status': self.status,
            'fim_status': self.fim_status,
            'vulnerabilities_count': self.vulnerabilities_count
        }

class WazuhRule:
    def __init__(self, rule_id, level, description, group_name, field_rules):
        self.id = rule_id
        self.level = level
        self.description = description
        self.group = group_name
        self.field_rules = field_rules # list of dicts: {'name': name, 'type': type, 'operator': operator, 'val': val}

    def match(self, data):
        # All field checks must pass for the rule to trigger (AND logic)
        if not self.field_rules:
            return False
            
        for rule in self.field_rules:
            field_name = rule['name']
            if field_name not in data:
                return False
                
            val = data[field_name]
            rule_val = rule['val']
            val_type = rule.get('type', 'str')
            op = rule.get('operator', 'eq')

            try:
                if val_type == 'float':
                    val = float(val)
                    rule_val = float(rule_val)
                elif val_type == 'int':
                    val = int(val)
                    rule_val = int(rule_val)
                else:
                    val = str(val).lower()
                    rule_val = str(rule_val).lower()
                    
                if op == 'eq' and val != rule_val:
                    return False
                elif op == 'gt' and val <= rule_val:
                    return False
                elif op == 'lt' and val >= rule_val:
                    return False
                elif op == 'ne' and val == rule_val:
                    return False
                elif op == 'contains' and rule_val not in val:
                    return False
            except Exception:
                return False
        return True

class WazuhAlert:
    def __init__(self, rule_id, level, description, agent_id, agent_name, details):
        self.uuid = str(uuid.uuid4())
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.rule_id = rule_id
        self.level = level
        self.description = description
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.details = details

    def to_dict(self):
        return {
            'uuid': self.uuid,
            'timestamp': self.timestamp,
            'rule_id': self.rule_id,
            'level': self.level,
            'description': self.description,
            'agent_id': self.agent_id,
            'agent_name': self.agent_name,
            'details': self.details
        }

class WazuhManager:
    def __init__(self, rules_filepath="wazuh_rules.xml"):
        self.rules_filepath = rules_filepath
        self.agents = {}
        self.rules = []
        self.alerts = []
        self.active_response_logs = []
        self.lock = threading.Lock()

        # Seed agents mapping to XDR endpoints
        self.register_agent(WazuhAgent("001", "WORKSTATION-TV-01", "192.168.1.15", "Linux IoT"))
        self.register_agent(WazuhAgent("002", "DEV-LAPTOP-WIN11", "192.168.1.24", "Windows 11 Enterprise"))
        self.register_agent(WazuhAgent("003", "SECURITY-CAM-01", "192.168.1.10", "Embedded Linux"))
        self.register_agent(WazuhAgent("004", "SMART-PLUG-HQ", "192.168.1.37", "FreeRTOS", "disconnected"))

        # Load rules from XML
        self.load_rules_from_file()

    def register_agent(self, agent):
        with self.lock:
            self.agents[agent.id] = agent

    def load_rules_from_file(self):
        try:
            with open(self.rules_filepath, 'r', encoding='utf-8') as f:
                xml_content = f.read()
            self.parse_rules_xml(xml_content)
            print(f"[+] Wazuh Rules Engine successfully loaded {len(self.rules)} rules.")
        except Exception as e:
            print(f"[!] Failed to load rules file {self.rules_filepath}: {e}")
            # Fallback hardcoded rules
            self.rules = [
                WazuhRule(100002, 12, "Mimikatz detected", "endpoint", [{'name': 'process_name', 'val': 'mimikatz.exe'}]),
                WazuhRule(200001, 10, "Network anomaly high score", "network", [{'name': 'score', 'type': 'float', 'operator': 'gt', 'val': 0.80}])
            ]

    def parse_rules_xml(self, xml_string):
        try:
            root = ET.fromstring(xml_string)
            new_rules = []
            
            # Find groups
            for group in root.findall('group'):
                group_name = group.get('name')
                for rule_node in group.findall('rule'):
                    rule_id = int(rule_node.get('id'))
                    level = int(rule_node.get('level'))
                    description = rule_node.find('description').text
                    
                    field_rules = []
                    for field in rule_node.findall('field'):
                        name = field.get('name')
                        val = field.text
                        val_type = field.get('type', 'str')
                        op = field.get('operator', 'eq')
                        field_rules.append({
                            'name': name,
                            'val': val,
                            'type': val_type,
                            'operator': op
                        })
                    
                    new_rules.append(WazuhRule(rule_id, level, description, group_name, field_rules))
            
            with self.lock:
                self.rules = new_rules
            return True, f"Successfully parsed {len(new_rules)} rules."
        except Exception as e:
            return False, f"XML Parsing Error: {str(e)}"

    def get_rules_xml_string(self):
        try:
            with open(self.rules_filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            return "<rules></rules>"

    def save_rules_xml_string(self, xml_string):
        success, msg = self.parse_rules_xml(xml_string)
        if success:
            try:
                with open(self.rules_filepath, 'w', encoding='utf-8') as f:
                    f.write(xml_string)
            except Exception as e:
                return False, f"Failed to write XML rules file: {e}"
        return success, msg

    def match_telemetry(self, group_name, data):
        matched_alerts = []
        # Find matching agent if IP or Hostname is present
        target_agent = None
        ip = data.get('ip') or data.get('src')
        host = data.get('host') or data.get('hostname')
        
        with self.lock:
            for agent in self.agents.values():
                if (ip and agent.ip == ip) or (host and agent.hostname == host):
                    target_agent = agent
                    break

        agent_id = target_agent.id if target_agent else "000"
        agent_name = target_agent.hostname if target_agent else "unknown-endpoint"

        for rule in self.rules:
            if rule.group == group_name:
                if rule.match(data):
                    alert = WazuhAlert(
                        rule_id=rule.id,
                        level=rule.level,
                        description=rule.description,
                        agent_id=agent_id,
                        agent_name=agent_name,
                        details=str(data)
                    )
                    with self.lock:
                        self.alerts.insert(0, alert)
                        if len(self.alerts) > 100:
                            self.alerts = self.alerts[:100]
                    matched_alerts.append(alert)
                    
                    # Log active response triggers for high level alerts
                    if rule.level >= 10:
                        self.log_active_response(
                            agent_name=agent_name,
                            action="Wazuh Active Response Playbook",
                            details=f"Rule {rule.id} (Level {rule.level}) matched: Triggering firewall-drop block script on Remote IP/Host."
                        )
        return matched_alerts

    def log_active_response(self, agent_name, action, details):
        log_entry = {
            'timestamp': datetime.datetime.now().strftime("%H:%M:%S"),
            'agent': agent_name,
            'action': action,
            'details': details
        }
        with self.lock:
            self.active_response_logs.insert(0, log_entry)
            if len(self.active_response_logs) > 50:
                self.active_response_logs = self.active_response_logs[:50]

    def trigger_agent_response(self, agent_id, action):
        with self.lock:
            agent = self.agents.get(agent_id)
        if not agent:
            return False, "Agent not found"

        if action == "fim_scan":
            if agent.fim_status == "scanning":
                return False, "FIM scan already running on agent"
            
            # Start background thread to simulate scan
            def run_scan():
                agent.fim_status = "scanning"
                self.log_active_response(agent.hostname, "syscheck_fim", "Initiating Syscheck FIM scan on agent directories.")
                time.sleep(4)
                agent.fim_status = "completed"
                self.log_active_response(agent.hostname, "syscheck_fim", "FIM integrity scan completed. 0 integrity anomalies found.")

            threading.Thread(target=run_scan, daemon=True).start()
            return True, "FIM scan initiated"
            
        elif action == "restart":
            self.log_active_response(agent.hostname, "agent_control", "Wazuh Agent restart request sent.")
            return True, "Agent restart command sent"
            
        return False, "Unknown action"

def test_parser():
    mgr = WazuhManager()
    print("[+] Test parsing XML configurations...")
    xml = mgr.get_rules_xml_string()
    success, msg = mgr.parse_rules_xml(xml)
    print(f"Result: {success}, Message: {msg}")
    
    # Test network rule matching
    flow_data = {'ip': '192.168.1.15', 'score': 0.95, 'packet_count': 100}
    alerts = mgr.match_telemetry("network", flow_data)
    print(f"Matched Alerts Count: {len(alerts)}")
    for a in alerts:
        print(f"Alert triggered: Rule {a.rule_id} Level {a.level} - {a.description}")

if __name__ == "__main__":
    test_parser()
