# AI Home Network Anomaly Detector

This is a Python-based project implementing a home-network intrusion and anomaly detector using the **Isolation Forest** Machine Learning algorithm. It replicates the core behavioral detection concept used by enterprise security platforms like **SentinelOne**, but tailored for a local home network environment.

---

## 🛠️ How it works

Unlike traditional antivirus programs or firewalls that use signature-based rules (looking for specific known files/actions), this system uses **Behavioral AI (Unsupervised Learning)**:

1. **Packet Sniffing**: Uses `Scapy` to listen to local network traffic.
2. **Feature Extraction**: Groups packet statistics over a sliding window (10 seconds) per local IP address.
3. **Behavioral AI (Isolation Forest)**: Trains a model on your normal home devices' behavior. Since anomalous actions (like network scanning, DDoS flooding, or massive uploading) are rare and look fundamentally different, the model naturally isolates and flags them.

---

## 🚀 Setup Instructions

1. **Activate the Virtual Environment**:
   ```powershell
   # On Windows Powershell
   .\venv\Scripts\activate
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 Running the Application

### 1. Simulation Mode (Recommended for testing)
To see the AI in action immediately without needing specialized network drivers or admin rights, run:
```bash
python traffic_monitor.py --mode simulate
```
**What happens:**
* Generates 250 normal flows (simulating IoT devices, smart TVs, and web browsing PCs).
* Trains the Isolation Forest model on this baseline.
* Mixes normal traffic with simulated attacks:
  * **Port Scan**: Scanning 50-150 unique ports from a single IP.
  * **DDoS Attack**: Flooding a single target with UDP packets.
  * **Data Exfiltration**: Uploading massive byte volumes in a short time.
* Streams and displays the detection output in real-time, coloring anomalies in **red/yellow** with an anomaly score.

### 2. Live Training Mode (Capture your actual home traffic)
To build a model based on your actual network devices:
```powershell
# Run as Administrator (Windows) or root (Linux)
python traffic_monitor.py --mode train --duration 300
```
* **Duration**: Collects normal baseline traffic for 300 seconds (5 minutes) and saves the model to `anomaly_detector.joblib`.
* **Important**: You must keep network usage **normal** during this phase so the AI doesn't learn malicious behavior as "normal".

### 3. Live Detection Mode
Once you have trained the model, launch real-time monitoring:
```powershell
# Run as Administrator (Windows) or root (Linux)
python traffic_monitor.py --mode detect
```
* If any device starts behaving abnormally compared to the trained baseline, the monitor will immediately output a red alert line to the console.

---

## ⚠️ Requirements for Live Sniffing on Windows
For Scapy to capture raw live packets on Windows:
1. **Npcap**: You must have Npcap (or WinPcap) installed. You can download Npcap from [npcap.com](https://npcap.com/).
2. **Admin Privileges**: Open Powershell or Command Prompt as **Administrator** before executing the scripts.
