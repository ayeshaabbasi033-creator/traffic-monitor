from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
from datetime import datetime

# This list will hold one dictionary per packet (a "row" of data)
captured_data = []

def extract_features(packet):
    # We only care about packets that have an IP layer
    if IP in packet:
        row = {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f"),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": packet[IP].proto,   # 6 = TCP, 17 = UDP
            "packet_size": len(packet),
            "src_port": None,
            "dst_port": None,
            "flags": None,
        }

        if TCP in packet:
            row["src_port"] = packet[TCP].sport
            row["dst_port"] = packet[TCP].dport
            row["flags"] = str(packet[TCP].flags)
        elif UDP in packet:
            row["src_port"] = packet[UDP].sport
            row["dst_port"] = packet[UDP].dport

        captured_data.append(row)
        print(f"Captured: {row['src_ip']}:{row['src_port']} -> {row['dst_ip']}:{row['dst_port']} ({row['packet_size']} bytes)")


print("Capturing 50 packets... press Ctrl+C to stop early")
sniff(prn=extract_features, count=50)

# Turn our list of dicts into a pandas DataFrame (like a spreadsheet)
df = pd.DataFrame(captured_data)

# Save it to a CSV so we can look at it / reuse it later
df.to_csv("captured_traffic.csv", index=False)

print(f"\nDone! Captured {len(df)} packets. Saved to captured_traffic.csv")
print("\nFirst few rows:")
print(df.head())