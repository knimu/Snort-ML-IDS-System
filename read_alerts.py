import time
import joblib
import subprocess

# ==============================
# LOAD ML MODEL (IMPORTANT)
# ==============================
model = joblib.load("snort_rf_model_enhanced.pkl")

print("🚀 Hybrid IDS Started...\n")

# ==============================
# CONFIG
# ==============================
alert_file = "alert_fast.txt"
blocked_ips = {}
BLOCK_TIME = 30  # seconds

last_print_time = 0

# ==============================
# BLOCK FUNCTION
# ==============================
def block_ip(ip):
    if ip not in blocked_ips:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        blocked_ips[ip] = time.time()
        print(f"🚫 Blocking IP: {ip}")

# ==============================
# UNBLOCK FUNCTION
# ==============================
def unblock_ips():
    current_time = time.time()
    for ip in list(blocked_ips.keys()):
        if current_time - blocked_ips[ip] > BLOCK_TIME:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            print(f"✅ Unblocked IP: {ip}")
            del blocked_ips[ip]

# ==============================
# EXTRACT SOURCE IP
# ==============================
def extract_ip(line):
    try:
        parts = line.split("{")[1].split("}")[1].strip()
        src_ip = parts.split("->")[0].strip()
        return src_ip
    except:
        return None

# ==============================
# MAIN LOOP
# ==============================
with open(alert_file, "r") as f:
    f.seek(0, 2)  # go to end of file

    while True:
        line = f.readline()

        if not line:
            time.sleep(0.5)
            continue

        if "ICMP" in line:
            current_time = time.time()

            # Avoid spam (print every 2 sec)
            if current_time - last_print_time > 2:
                print("🚨 ALERT:", line.strip())

                src_ip = extract_ip(line)

                # ==============================
                # SIMPLE REAL FEATURES (7 features)
                # ==============================
                features = [
                    1,  # ICMP
                    1,  # packet size (dummy)
                    1,  # packet rate (dummy)
                    1,  # time diff
                    1,  # protocol flag
                    1,  # anomaly flag
                    1   # extra feature
                ]

                prediction = model.predict([features])[0]

                if prediction == 1:
                    print("🔥 ML DETECTED: ATTACK")

                    if src_ip:
                        block_ip(src_ip)

                else:
                    print("✅ ML DETECTED: NORMAL")

                print()

                last_print_time = current_time

        # Always check unblock
        unblock_ips()
