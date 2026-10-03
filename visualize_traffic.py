import pandas as pd
import matplotlib.pyplot as plt

# Load the traffic data we captured earlier with feature_extract.py
df = pd.read_csv("captured_traffic.csv")

# Chart 1: Packet size for each captured packet, in order
plt.figure(figsize=(10, 5))
plt.plot(df["packet_size"], marker="o", linestyle="-", markersize=3)
plt.title("Packet Size Over Captured Traffic")
plt.xlabel("Packet number (in capture order)")
plt.ylabel("Packet size (bytes)")
plt.tight_layout()
plt.savefig("packet_sizes.png")
print("Saved packet_sizes.png")

# Chart 2: How many packets used each protocol
plt.figure(figsize=(6, 5))
df["protocol"].value_counts().plot(kind="bar", color="#58a6ff")
plt.title("Packet Count by Protocol")
plt.xlabel("Protocol (6=TCP, 17=UDP)")
plt.ylabel("Number of packets")
plt.tight_layout()
plt.savefig("protocol_counts.png")
print("Saved protocol_counts.png")