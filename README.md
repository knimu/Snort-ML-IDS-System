# Hybrid Snort + Machine Learning Intrusion Detection System

A hybrid Intrusion Detection and Prevention System (IDPS) developed using Snort 3, Machine Learning, and Python.

The project combines signature-based detection with behavioral analysis and a machine learning model to monitor network traffic, classify suspicious activity, automatically block malicious IP addresses using iptables, and visualize alerts on a real-time Flask dashboard.

---

## Project Overview

Traditional Intrusion Detection Systems such as Snort are very effective at identifying attacks that match predefined rules. However, they depend on signatures and cannot independently identify every suspicious traffic pattern.

This project combines three detection approaches:

- Signature-based detection using Snort 3
- Behavioral analysis using traffic characteristics
- Machine Learning-based classification

The system continuously reads Snort alerts, extracts useful traffic features, evaluates them using predefined behavioral rules and a trained machine learning model, stores the results, blocks malicious IP addresses when an attack is detected, and displays all events on a live dashboard.

---

## Features

- Signature-based intrusion detection using Snort 3
- Behavioral detection based on packet rate and traffic patterns
- Machine Learning classification using a trained Random Forest model
- Automatic IP blocking using iptables
- Real-time monitoring dashboard built with Flask
- Live attack statistics and traffic visualization
- Alert logging in JSON format
- Dataset generation for future model training
- Detection of ICMP and network scanning traffic using Snort rules

---

## System Architecture

```
                Network Traffic
                       │
                       ▼
                  Snort 3 IDS
                       │
               Snort Alert Output
                       │
                       ▼
            Python Hybrid Detection Engine
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
 Behavioral Rules   ML Prediction   Alert Logging
        │              │
        └───────Decision Engine──────┘
                       │
              Attack / Normal
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
   Block IP using iptables      Store Alert
                                         │
                                         ▼
                                 Flask Dashboard
```

---

## Technologies Used

| Component | Technology |
|----------|------------|
| IDS | Snort 3 |
| Programming Language | Python |
| Machine Learning | Scikit-learn |
| Dashboard | Flask |
| Frontend | HTML, CSS, JavaScript |
| Charts | Chart.js |
| Operating System | Ubuntu |
| Firewall | iptables |
| Virtualization | VMware |

---

## Project Structure

```
Snort-ML-IDS-System/

│
├── dashboard/
│   ├── static/
│   ├── templates/
│   ├── alerts.json
│   └── app.py
│
├── dataset.csv
├── hybrid_final_ids.py
├── model.pkl
├── train_model.py
├── requirements.txt
└── README.md
```

---

## Detection Workflow

### 1. Snort Detection

Snort monitors network traffic and generates alerts whenever a packet matches a configured rule.

Example:

- ICMP Ping
- Nmap Scan

These alerts are passed to the Python detection script.

---

### 2. Feature Extraction

For every alert, the following features are generated:

- Packet Rate
- Number of Unique Source IPs
- Average Packet Interval
- Burst Flag

These values are used by both the behavioral detection logic and the machine learning model.

---

### 3. Behavioral Detection

Traffic is classified as suspicious when it satisfies predefined conditions such as:

- High packet rate
- Very small packet interval
- Burst traffic

---

### 4. Machine Learning Prediction

The extracted features are passed to a trained Random Forest model.

The model predicts whether the traffic resembles an attack or normal activity.

---

### 5. Final Decision

The final decision combines:

- Behavioral analysis
- Machine Learning prediction

If an attack is detected:

- Alert is stored
- Dataset is updated
- Source IP is blocked using iptables

Otherwise, the traffic is recorded as normal.

---

## Dashboard

The Flask dashboard displays:

- Total traffic
- Attack count
- Normal traffic count
- Recent alerts
- Packet rate
- Risk indicator
- Attack distribution charts
- List of blocked IP addresses

Dashboard data is updated automatically using API endpoints.

---

## Dataset

The project generates a dataset during execution.

Each record contains:

| Feature |
|----------|
| packet_rate |
| unique_src_ips |
| avg_interval |
| burst_flag |
| label |

Label:

- 0 → Normal
- 1 → Attack

The dataset can be used for retraining the machine learning model.

---

## Automatic IP Blocking

When an attack is detected, the source IP address is blocked using iptables.

Example:

```
iptables -A INPUT -s <IP> -j DROP
iptables -A OUTPUT -d <IP> -j DROP
```

Blocked IP addresses are also displayed on the dashboard.

---

## Machine Learning Model

Algorithm used:

- Random Forest Classifier

Libraries:

- pandas
- scikit-learn
- joblib

Input Features:

- packet_rate
- unique_src_ips
- avg_interval
- burst_flag

Output:

- Attack
- Normal

---

## Running the Project

### Clone the repository

```bash
git clone https://github.com/knimu/Snort-ML-IDS-System.git

cd Snort-ML-IDS-System
```

---

### Install dependencies

```bash
pip install -r requirements.txt
```

---

### Start Snort

```bash
sudo snort -q \
-c /etc/snort/snort.lua \
-i <interface> \
-A fast
```

---

### Run Hybrid Detection

```bash
python3 hybrid_final_ids.py
```

---

### Start Dashboard

```bash
cd dashboard

python3 app.py
```

Open:

```
http://127.0.0.1:5000
```

---

## Testing

The project was tested using:

- ICMP Ping
- Nmap Ping Scan
- Snort Local Rules

The generated alerts were processed by the hybrid detection engine and displayed on the dashboard.

---

## Current Limitations

- Currently processes Snort alert output rather than raw packets.
- Machine learning model uses a small set of traffic features.
- Detection logic is based on predefined behavioral thresholds.
- IP blocking uses local iptables rules on the host machine.
- The system has been tested in a VMware-based Ubuntu environment.

---

## Future Improvements

Possible extensions include:

- Support for additional attack types
- Flow-based feature extraction
- Database storage for alerts
- User authentication for the dashboard
- Integration with SIEM platforms
- Email or SMS notifications
- Model retraining using larger datasets

---

## Authors

Nimisha Khanzode

Vishwakarma Institute of Technology, Pune

B.Tech Computer Science and Engineering

---

## License

This project is developed for educational and academic purposes.
