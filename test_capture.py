from scapy.all import sniff

def show_packet(packet):
    print(packet.summary())

print("Starting capture... press Ctrl+C to stop")
sniff(prn=show_packet, count=10)