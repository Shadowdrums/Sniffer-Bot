from scapy.all import *
from datetime import datetime, timedelta

# Dictionary to store IP addresses and their associated activity
ip_activity = {}

# Open file for writing suspicious activity to
bad_traffic_file = open("BadTraffic.txt", "w")

def packet_callback(packet):
    # Only process IP packets
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Define the packet type and connection type
        if TCP in packet:
            packet_type = "TCP"
            connection_type = packet[TCP].flags
        elif UDP in packet:
            packet_type = "UDP"
            connection_type = "N/A"
        elif ICMP in packet:
            packet_type = "ICMP"
            connection_type = "N/A"
        else:
            packet_type = "Unknown"
            connection_type = "N/A"

        # Check for scanning activity
        if TCP in packet and packet[TCP].flags == "S":
            print(f"[{datetime.now()}] WARNING: {src_ip} is scanning {dst_ip} ({packet_type} {connection_type} packet)!")
            print(packet.summary())
            # Write suspicious activity to file
            bad_traffic_file.write(f"[{datetime.now()}] WARNING: {src_ip} is scanning {dst_ip} ({packet_type} {connection_type} packet)!\n")
            bad_traffic_file.write(f"{packet.summary()}\n")

            # Update activity dictionary
            if src_ip in ip_activity:
                ip_activity[src_ip]["scans"] += 1
            else:
                ip_activity[src_ip] = {"scans": 1, "pings": 0}

        # Check for pinging activity
        elif ICMP in packet and packet[ICMP].type == 8:
            print(f"[{datetime.now()}] WARNING: {src_ip} is pinging {dst_ip} ({packet_type} {connection_type} packet)!")
            print(packet.summary())
            # Write suspicious activity to file
            bad_traffic_file.write(f"[{datetime.now()}] WARNING: {src_ip} is pinging {dst_ip} ({packet_type} {connection_type} packet)!\n")
            bad_traffic_file.write(f"{packet.summary()}\n")

            # Update activity dictionary
            if src_ip in ip_activity:
                ip_activity[src_ip]["pings"] += 1
            else:
                ip_activity[src_ip] = {"scans": 0, "pings": 1}

        # Check for suspicious activity
        elif dst_ip in ip_activity and \
            (ip_activity[dst_ip].get("scans", 0) >= 5 or \
             (ip_activity[dst_ip].get("pings", 0) >= 5 and datetime.now() - ip_activity[dst_ip].get("last_ping", datetime.now()) <= timedelta(seconds=5))):
           print(f"[{datetime.now()}] WARNING: {dst_ip} is under attack from {src_ip} ({packet_type} {connection_type} packet)!")
           print(packet.summary())
         # Write suspicious activity to file
           bad_traffic_file.write(f"[{datetime.now()}] WARNING: {dst_ip} is under attack from {src_ip} ({packet_type} {connection_type} packet)!\n")
           bad_traffic_file.write(f"{packet.summary()}\n")


        # Update activity dictionary
        if src_ip in ip_activity:
            ip_activity[src_ip]["last_activity"] = datetime.now()
        else:
            ip_activity[src_ip] = {"last_activity": datetime.now()}

# Print an opening message
print("Starting SnifferBot...")

# Sniff network traffic indefinitely
sniff(prn=packet_callback)
