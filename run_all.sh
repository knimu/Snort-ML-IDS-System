#!/bin/bash

echo "🚀 Starting HYBRID IDS SYSTEM..."

# ───────── SNORT ─────────

gnome-terminal -- bash -c "
echo '🔴 SNORT STARTED';
cd ~/snort_project;
sudo snort -q -l . -i ens37 -A fast -c /etc/snort/snort.conf;
exec bash"

# ───────── IDS ─────────

gnome-terminal -- bash -c "
echo '🟡 IDS ENGINE STARTED';
cd ~/snort_project;
source ml_env/bin/activate;
tail -f alert_fast.txt | python3 hybrid_final_ids.py;
exec bash"

# ───────── DASHBOARD ─────────

gnome-terminal -- bash -c "
echo '🔵 DASHBOARD STARTED';
cd ~/snort_project;
source ml_env/bin/activate;
cd dashboard;
python3 app.py;
exec bash"

echo "✅ ALL SYSTEMS LAUNCHED"
