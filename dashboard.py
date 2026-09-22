import warnings
warnings.filterwarnings("ignore")

from flask import Flask, render_template_string, jsonify
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import joblib
from collections import deque
import threading
import time

app = Flask(__name__)

# ---------------------------------------------------------
# Load the trained model (same as live_detect_v2.py)
# ---------------------------------------------------------
model = joblib.load("traffic_model.pkl")
encoders = joblib.load("encoders.pkl")
feature_cols = joblib.load("feature_cols.pkl")

WINDOW_SECONDS = 2
history = deque()  # rolling connection history, used for feature calculation
recent_events = deque(maxlen=50)  # what we show on the dashboard (most recent 50)

# Simple running stats
stats = {"total_packets": 0, "alerts": 0, "normal": 0}
stats_lock = threading.Lock()

PROTO_MAP = {6: "tcp", 17: "udp", 1: "icmp"}


def guess_service(dport):
    mapping = {80: "http", 443: "http", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain_u"}
    if dport in mapping:
        return mapping[dport]
    return f"port_{dport}"


def prune_old(now):
    while history and now - history[0][0] > WINDOW_SECONDS:
        history.popleft()


def build_feature_row(packet):
    if IP not in packet:
        return None

    now = time.time()
    dst_ip = packet[IP].dst
    proto_num = packet[IP].proto
    proto_name = PROTO_MAP.get(proto_num, "tcp")

    dport = None
    service = "other"
    if TCP in packet:
        dport = packet[TCP].dport
        service = guess_service(dport)
    elif UDP in packet:
        dport = packet[UDP].dport
        service = "domain_u"

    history.append((now, dst_ip, dport, service))
    prune_old(now)

    same_host_conns = [h for h in history if h[1] == dst_ip]
    count = len(same_host_conns)
    same_srv_conns = [h for h in same_host_conns if h[3] == service]
    srv_count = len(same_srv_conns)
    same_srv_rate = srv_count / count if count else 0
    diff_srv_rate = 1 - same_srv_rate
    dst_host_count = len(history)

    row = {col: 0 for col in feature_cols}
    row["protocol_type"] = proto_name
    row["service"] = service
    row["flag"] = "SF"
    row["src_bytes"] = len(packet)
    row["count"] = count
    row["srv_count"] = srv_count
    row["same_srv_rate"] = same_srv_rate
    row["diff_srv_rate"] = diff_srv_rate
    row["dst_host_count"] = dst_host_count
    row["dst_host_srv_count"] = srv_count
    row["dst_host_same_srv_rate"] = same_srv_rate
    row["dst_host_diff_srv_rate"] = diff_srv_rate

    return row, count, diff_srv_rate


def process_packet(packet):
    result = build_feature_row(packet)
    if result is None:
        return
    row, count, diff_srv_rate = result

    df_row = pd.DataFrame([row])[feature_cols]
    for col, le in encoders.items():
        val = df_row.at[0, col]
        df_row[col] = le.transform([val])[0] if val in le.classes_ else 0

    prediction = model.predict(df_row)[0]
    src = packet[IP].src
    dst = packet[IP].dst

    with stats_lock:
        stats["total_packets"] += 1
        if prediction == "attack":
            stats["alerts"] += 1
        else:
            stats["normal"] += 1

    recent_events.appendleft({
        "time": time.strftime("%H:%M:%S"),
        "src": src,
        "dst": dst,
        "size": len(packet),
        "prediction": prediction,
        "count": count,
        "diff_srv_rate": round(diff_srv_rate, 2),
    })


def capture_loop():
    # Runs forever in the background, feeding packets into process_packet
    sniff(prn=process_packet, store=False)


# ---------------------------------------------------------
# Web page
# ---------------------------------------------------------
PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>AI Traffic Monitor</title>
    <meta http-equiv="refresh" content="2">
    <style>
        body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
        h1 { color: #58a6ff; }
        .stats { display: flex; gap: 20px; margin-bottom: 20px; }
        .stat-box { background: #161b22; padding: 15px 25px; border-radius: 8px; border: 1px solid #30363d; }
        .stat-box .num { font-size: 28px; font-weight: bold; }
        .alerts .num { color: #f85149; }
        .normal .num { color: #3fb950; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #30363d; }
        th { color: #8b949e; }
        .row-attack { background: rgba(248, 81, 73, 0.15); }
        .badge-attack { color: #f85149; font-weight: bold; }
        .badge-normal { color: #3fb950; }
    </style>
</head>
<body>
    <h1>🛡️ AI Traffic Monitor</h1>
    <div class="stats">
        <div class="stat-box"><div class="num">{{ total }}</div>Total Packets</div>
        <div class="stat-box normal"><div class="num">{{ normal }}</div>Normal</div>
        <div class="stat-box alerts"><div class="num">{{ alerts }}</div>Alerts</div>
    </div>
    <table>
        <tr><th>Time</th><th>Source</th><th>Destination</th><th>Size</th><th>Count</th><th>Diff Srv Rate</th><th>Status</th></tr>
        {% for e in events %}
        <tr class="{{ 'row-attack' if e.prediction == 'attack' else '' }}">
            <td>{{ e.time }}</td>
            <td>{{ e.src }}</td>
            <td>{{ e.dst }}</td>
            <td>{{ e.size }}</td>
            <td>{{ e.count }}</td>
            <td>{{ e.diff_srv_rate }}</td>
            <td class="{{ 'badge-attack' if e.prediction == 'attack' else 'badge-normal' }}">
                {{ '🚨 ATTACK' if e.prediction == 'attack' else 'OK' }}
            </td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""


@app.route("/")
def dashboard():
    with stats_lock:
        s = dict(stats)
    return render_template_string(PAGE, total=s["total_packets"], normal=s["normal"],
                                   alerts=s["alerts"], events=list(recent_events))


if __name__ == "__main__":
    # Start packet capture in a background thread so it doesn't block the web server
    capture_thread = threading.Thread(target=capture_loop, daemon=True)
    capture_thread.start()

    print("Dashboard starting at http://127.0.0.1:5000")
    app.run(debug=False, port=5000)