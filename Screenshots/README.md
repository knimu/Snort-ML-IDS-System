# Hybrid Intrusion Detection and Prevention System (Hybrid IDS/IPS)

A real-time **Hybrid Intrusion Detection and Prevention System** that combines **Snort 3 signature-based detection** with **Machine Learning-based anomaly detection**. The system automatically detects malicious traffic, blocks attackers using IPTables, logs events, and visualizes network activity through a real-time Flask dashboard.

---

## Features

- Signature-Based Intrusion Detection using Snort 3
- Machine Learning-Based Attack Detection
- Automatic IP Blocking using IPTables
- Real-Time Flask Dashboard
- Live Attack Monitoring
- Normal vs Attack Traffic Visualization
- Traffic Rate Graph
- Attack Ratio Chart
- Top Attacking IPs
- Automatic JSON Alert Logging
- Dataset Generation for Model Improvement

---

# Technologies Used

## Security

- Snort 3
- IPTables

## Machine Learning

- Python
- Pandas
- Scikit-Learn
- Joblib

## Dashboard

- Flask
- HTML
- CSS
- JavaScript
- Chart.js

## Operating System

- Ubuntu 24.04
- VMware Workstation

---

# System Architecture

```
                +----------------+
                |  Attacker VM   |
                +-------+--------+
                        |
                        |
                 Network Traffic
                        |
                        v
                +----------------+
                |    Snort IDS   |
                +-------+--------+
                        |
                Signature Alerts
                        |
                        v
          +---------------------------+
          | Hybrid IDS Engine         |
          |                           |
          | • Behavioral Detection    |
          | • Machine Learning Model  |
          +-------------+-------------+
                        |
         +--------------+--------------+
         |                             |
         |                             |
     alerts.json                  dataset.csv
         |                             |
         +--------------+--------------+
                        |
                        v
                Flask Dashboard
```

---

# Project Workflow

1. Network packets are captured by Snort 3.
2. Snort generates signature-based alerts.
3. Alerts are forwarded to the Hybrid IDS engine.
4. Network features are extracted:
   - Packet Rate
   - Unique Source IPs
   - Average Packet Interval
   - Burst Flag
5. The Machine Learning model classifies traffic.
6. Behavioral rules validate the attack.
7. Malicious IPs are blocked using IPTables.
8. Alerts are stored in `alerts.json`.
9. Features are stored in `dataset.csv`.
10. The Flask dashboard displays live monitoring information.

---

# Project Structure

```
Snort-ML-IDS-System
│
├── dashboard/
│
├── screenshots/
│   ├── dashboard-running.png
│   ├── normal-traffic-1.png
│   ├── normal-traffic-2.png
│   ├── live-attack-1.png
│   ├── live-attack-2.png
│   ├── attack-detected-terminal.png
│   ├── normal-detected-terminal.png
│   ├── blocked-ip-terminal.png
│   ├── dataset-logging.png
│   ├── json-alert-logging.png
│   └── attacker-vm.png
│
├── hybrid_final_ids.py
├── start_system.sh
├── dataset.csv
├── alerts.json
└── README.md
```

---

# Installation

Clone the repository

```bash
git clone https://github.com/yourusername/Snort-ML-IDS-System.git

cd Snort-ML-IDS-System
```

Activate the virtual environment

```bash
source ml_env/bin/activate
```

Start the Flask dashboard

```bash
cd dashboard
python3 app.py
```

Start the Hybrid IDS

```bash
cd ..

sudo stdbuf -oL snort \
-q \
-c /etc/snort/snort.conf \
-i ens33 \
-A fast \
-k none | python3 hybrid_final_ids.py
```

---

# Attack Simulation

Generate normal traffic

```bash
ping 192.168.76.129
```

Generate attack traffic

```bash
hping3 --icmp --flood 192.168.76.129
```

---
# Screenshots

## Dashboard Running

![Dashboard](Screenshots/dashboard-running.png)

---

## Normal Traffic Detection

![Normal Traffic 1](Screenshots/normal-traffic-1.png)

![Normal Traffic 2](Screenshots/normal-traffic-2.png)

---

## Live Attack Detection

![Attack 1](Screenshots/live-attack-1.png)

![Attack 2](Screenshots/live-attack-2.png)

---

## Hybrid IDS Terminal (Attack)

![Attack Terminal](Screenshots/attack-terminal.png)

---

## Hybrid IDS Terminal (Normal)

![Normal Terminal](Screenshots/normal-terminal.png)

---

## Automatic IP Blocking

![Blocked IP](Screenshots/blocked-ip-terminal.png)

---

## Dataset Logging

![Dataset Logging](Screenshots/dataset-logging.png)

---

## JSON Alert Logging

![JSON Logging](Screenshots/json-logging.png)

---

## Attacker VM

![Attacker VM](Screenshots/attacker-vm.png)

---

# Results

- Successfully detected normal network traffic.
- Successfully detected malicious traffic using hybrid detection.
- Automatically blocked malicious IP addresses using IPTables.
- Logged alerts in JSON format.
- Generated datasets for continuous ML improvement.
- Displayed real-time traffic statistics through the Flask dashboard.

---

# Future Improvements

- Deep Learning-based IDS
- Email Notifications
- SMS Alerts
- Threat Intelligence Integration
- Multi-Class Attack Classification
- Cloud Deployment
- SIEM Integration

---

# Author

**Nimisha Manoj Khanzode**

B.Tech Computer Science Engineering

IoT and Cybersecurity including Blockchain Technology

Vishwakarma Institute of Technology (VIT), Pune

---

## License

This project is developed for educational and academic purposes.
