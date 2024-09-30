#!/usr/bin/env python3
import socket
import sys
from scapy.all import *
from statistics import mean
from collections import Counter
import time
import requests

# Global variables to store packet sizes and DNS queries
packet_sizes = []
dns_queries = []
connection_attempts = {}

# IP address and port of the server to monitor
server_ip = "127.0.0.1"
server_port = 80  # Local Apache2 server port

# Threshold for detecting port scan attacks
PORT_SCAN_THRESHOLD = 5  # Adjust as needed

def raise_alarm(message):
    # Send alert message to the local Apache2 server via HTTP POST
    try:
        url = f"http://{server_ip}/alert.php"
        response = requests.post(url, data=message.encode())
        if response.status_code == 200:
            print("NIDS Alarm Sent:", message)
        else:
            print("Failed to send NIDS alarm:", response.status_code)
    except Exception as e:
        print("Failed to send NIDS alarm:", e)

def detect_attack(packet):
    if IP in packet and packet[IP].dst == server_ip and TCP in packet and Raw in packet:
        payload = packet[TCP].payload
        if b"cmd.exe" in payload:
            raise_alarm("Suspicious Command Executed - {}".format(payload))

def detect_anomaly(packet):
    if IP in packet and len(packet) > 1500:  # Compare with MTU size
        raise_alarm("Anomaly Detected: Packet Size Exceeds MTU - {}".format(packet.summary()))

def generate_dns_rules(packet):
    global dns_queries
    if DNS in packet:
        dns_queries.append(packet[DNS].qd.qname.decode())
        most_common_query = Counter(dns_queries).most_common(1)
        if most_common_query and most_common_query[0][1] > 5:
            raise_alarm("Potential DNS Amplification Attack Detected: {}".format(most_common_query[0][0]))

def monitor_traffic(packet):
    if IP in packet:
        packet_sizes.append(len(packet))
        avg_size = mean(packet_sizes)
        if abs(len(packet) - avg_size) > 50:
            raise_alarm("Anomaly Detected: Deviation from Average Packet Size - {}".format(packet.summary()))

def detect_port_scan(packet):
    global connection_attempts
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        if src_ip not in connection_attempts:
            connection_attempts[src_ip] = time.time()
        else:
            if time.time() - connection_attempts[src_ip] <= 10:
                connection_attempts[src_ip] += 1
                if connection_attempts[src_ip] >= PORT_SCAN_THRESHOLD:
                    raise_alarm("Port Scan Attack Detected: Source IP {} is scanning multiple ports".format(src_ip))
            else:
                connection_attempts[src_ip] = time.time()
        cleanup_old_connection_attempts()

def cleanup_old_connection_attempts():
    global connection_attempts
    current_time = time.time()
    for src_ip in list(connection_attempts.keys()):
        if current_time - connection_attempts[src_ip] > 10:
            del connection_attempts[src_ip]

def main():
    print("NIDS is monitoring the network traffic.")
    # No need to connect to the server explicitly

    # Start sniffing and detecting attacks
    sniff(prn=lambda x: (detect_attack(x), detect_anomaly(x), generate_dns_rules(x), monitor_traffic(x), detect_port_scan(x)), store=0)

if __name__ == "__main__":
    main()