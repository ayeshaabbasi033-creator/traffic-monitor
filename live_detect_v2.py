import warnings
warnings.filterwarnings("ignore")
import os
os.environ["PYTHONWARNINGS"] = "ignore"

from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import joblib
from collections import deque
import time

# ---------------------------------------------------------
# STEP 1: Load our trained model and helpers
# ---------------------------------------------------------
model = joblib.load("traffic_model.pkl")
encoders = joblib.load("encoders.pkl")
feature_cols = joblib.load("feature_cols.pkl")

print(f"Loaded model. It expects these {len(feature_cols)} features.\n")

# ---------------------------------------------------------
# STEP 2: Rolling connection history
# ---------------------------------------------------------
# NSL-KDD's "count" / "srv_count" / "diff_srv_rate" features are based on
# the last 2 seconds of traffic to the SAME destination host. We recreate
# that here by keeping a short rolling history of recent connections.
WINDOW_SECONDS = 2
history = deque()  # each entry: (timestamp, dst_ip, dst_port, service)

PROTO_MAP = {6: "tcp", 17: "udp", 1: "icmp"}


def guess_service(dport):
    mapping = {80: "http", 443: "http", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain_u"}
    if dport in mapping:
        return mapping[dport]
    # Treat each unrecognized port as its own distinct "service" so that
    # scanning many different ports actually registers as many different
    # services -- otherwise they'd all get lumped into one "other" bucket
    # and diff_srv_rate would never rise during a scan.
    return f"port_{dport}"


def prune_old(now):
    while history and now - history[0][0] > WINDOW_SECONDS:
        history.popleft()


def build_feature_row(packet):
    if IP not in packet:
        return None

    now = time.time()
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto_num = packet[IP].proto
    proto_name = PROTO_MAP.get(proto_num, "tcp")

    dport = None
    service = "other"
    flag = "SF"
    if TCP in packet:
        dport = packet[TCP].dport
        service = guess_service(dport)
    elif UDP in packet:
        dport = packet[UDP].dport
        service = "domain_u"

    # Record this connection, then drop anything older than our window
    history.append((now, dst_ip, dport, service))
    prune_old(now)

    # --- Compute the real rolling-window stats ---
    # count: how many connections (in the window) went to the SAME destination host
    same_host_conns = [h for h in history if h[1] == dst_ip]
    count = len(same_host_conns)

    # srv_count: of those, how many were to the SAME service (e.g. same port type)
    same_srv_conns = [h for h in same_host_conns if h[3] == service]
    srv_count = len(same_srv_conns)

    # same_srv_rate: fraction of connections to this host that used the same service
    same_srv_rate = srv_count / count if count else 0

    # diff_srv_rate: fraction that used a DIFFERENT service -- this is the
    # key signal for a port scan, since scans hit many different ports/services rapidly
    diff_srv_rate = 1 - same_srv_rate

    # dst_host_count: how many total connections (any host) happened in this window,
    # a rough proxy for "how busy/bursty is traffic right now"
    dst_host_count = len(history)

    row = {col: 0 for col in feature_cols}
    row["protocol_type"] = proto_name
    row["service"] = service
    row["flag"] = flag
    row["src_bytes"] = len(packet)
    row["dst_bytes"] = 0
    row["count"] = count
    row["srv_count"] = srv_count
    row["same_srv_rate"] = same_srv_rate
    row["diff_srv_rate"] = diff_srv_rate
    row["dst_host_count"] = dst_host_count
    row["dst_host_srv_count"] = srv_count
    row["dst_host_same_srv_rate"] = same_srv_rate
    row["dst_host_diff_srv_rate"] = diff_srv_rate

    return row


def process_packet(packet):
    row = build_feature_row(packet)
    if row is None:
        return

    df_row = pd.DataFrame([row])[feature_cols]

    for col, le in encoders.items():
        val = df_row.at[0, col]
        if val in le.classes_:
            df_row[col] = le.transform([val])
        else:
            df_row[col] = 0

    prediction = model.predict(df_row)[0]
    src = packet[IP].src
    dst = packet[IP].dst

    if prediction == "attack":
        print(f"ALERT: {src} -> {dst} | size={len(packet)} | count={row['count']} diff_srv_rate={row['diff_srv_rate']:.2f}")
    else:
        print(f"OK: {src} -> {dst} | size={len(packet)} | count={row['count']} diff_srv_rate={row['diff_srv_rate']:.2f}")


print("Starting live detection... press Ctrl+C to stop\n")
sniff(prn=process_packet, count=300)
