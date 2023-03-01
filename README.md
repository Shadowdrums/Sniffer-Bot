# Sniffer-Bot
A bot to monitor network traffic

This is a Python script that uses the Scapy library to sniff network traffic and detect suspicious activity. It defines a packet_callback function that is called for each packet that is captured by the sniffer.

The script starts by importing the necessary libraries and opening a file to write suspicious activity to. It then defines a dictionary called ip_activity that will store information about IP addresses and their associated activity.

The packet_callback function is defined to take a single argument, which is a packet object. The function checks if the packet is an IP packet by checking if the IP protocol is present in the packet. If it is, it extracts the source and destination IP addresses from the packet.

The function then determines the packet type (TCP, UDP, ICMP, or unknown) and connection type (if the packet is a TCP packet). If the packet is a TCP packet and the SYN flag is set (indicating a TCP scan), the function prints a warning message and writes the suspicious activity to the bad_traffic_file. It also updates the ip_activity dictionary to track the scanning activity.

If the packet is an ICMP packet and the type is an echo request (indicating a ping), the function prints a warning message and writes the suspicious activity to the bad_traffic_file. It also updates the ip_activity dictionary to track the pinging activity.

If the destination IP address is found in the ip_activity dictionary and it has received 5 or more scans or pings in the last 5 seconds, the function prints a warning message and writes the suspicious activity to the bad_traffic_file.

Finally, the function updates the ip_activity dictionary to track the last activity time for the source IP address.

The script then prints an opening message and starts sniffing network traffic indefinitely using the sniff function from Scapy. Each packet that is captured by the sniffer is passed to the packet_callback function for processing.
