#!/bin/bash

echo "=================================="
echo " STARTING HYBRID IDS/IPS SYSTEM "
echo "=================================="

echo "[1] Activating ML Environment..."
source ~/snort_project/ml_env/bin/activate

echo "[2] Starting Flask Dashboard..."
cd ~/snort_project/dashboard
gnome-terminal -- bash -c "source ../ml_env/bin/activate && python3 app.py; exec bash"

sleep 3

echo "[3] Starting Hybrid IDS Engine..."
gnome-terminal -- bash -c "
source ~/snort_project/ml_env/bin/activate &&
cd ~/snort_project &&
sudo stdbuf -oL snort -q \
-c /etc/snort/snort.conf \
-i ens33 \
-A alert_fast \
-k none 2>/dev/null |
stdbuf -oL python3 hybrid_final_ids.py;
exec bash"

echo "=================================="
echo " SYSTEM STARTED SUCCESSFULLY "
echo "=================================="
