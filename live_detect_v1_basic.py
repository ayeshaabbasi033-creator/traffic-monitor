import warnings
warnings.filterwarnings("ignore", category=UserWarning)

from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import joblib
from collections import defaultdict
import time

# ---------------------------------------------------------
# STEP 1: Load our trained model and helpers
# ---------------------------------------------------------
model = joblib.load("traffic_model.pkl")
encoders = joblib.load("encoders.pkl")
feature_cols = joblib.load("feature_cols.pkl")

print(f"Loaded model. It expects these {len(feature_cols)} features:")
print(feature_cols)

# ---------------------------------------------------------
# STEP 2: Track basic connection stats
# ---------------------------------------------------------
# NSL-KDD's features are based on whole connections, not single packets.
# We keep a running tally per (src_ip, dst_ip) pair to approximate that.
connection_stats = defaultdict(lambda: {"count": 0, "total_bytes": 0, "start_time": time.time()})

# Map numeric IP protocol to text, since the model was trained on text protocol names
PROTO_MAP = {6: "tcp", 17: "udp", 1: "icmp"}


def build_feature_row(packet):
    """
    Build one row shaped like the NSL-KDD features, using what we can
    measure from a live packet. Fields we can't truly measure (like error
    rates over time) get reasonable default values (mostly 0).
    """
    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto_num = packet[IP].proto
    proto_name = PROTO_MAP.get(proto_num, "tcp")  # default to tcp if unknown

    key = (src_ip, dst_ip)
    connection_stats[key]["count"] += 1
    connection_stats[key]["total_bytes"] += len(packet)

    service = "other"
    flag = "SF"
    if TCP in packet:
        dport = packet[TCP].dport
        # crude port -> service guess, extend this over time
        if dport == 80:
            service = "http"
        elif dport == 443:
            service = "http"  # NSL-KDD predates modern https labeling; close enough
        elif dport == 21:
            service = "ftp"
        elif dport == 22:
            service = "ssh"
        flag = "SF"
    elif UDP in packet:
        service = "domain_u"

    row = {col: 0 for col in feature_cols}  # start everything at 0
    row["protocol_type"] = proto_name
    row["service"] = service
    row["flag"] = flag
    row["src_bytes"] = len(packet)
    row["dst_bytes"] = 0
    row["count"] = connection_stats[key]["count"]

    return row


def process_packet(packet):
    row = build_feature_row(packet)
    if row is None:
        return

    df_row = pd.DataFrame([row])[feature_cols]

    # Apply the same encoders used during training, to keep values consistent.
    # Any brand-new category we haven't seen gets mapped to 0 safely.
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
        print(f"🚨 ALERT: possible attack | {src} -> {dst} | size={len(packet)}")
    else:
        print(f"OK: {src} -> {dst} | size={len(packet)}")


print("\nStarting live detection... press Ctrl+C to stop\n")
sniff(prn=process_packet, count=300)
