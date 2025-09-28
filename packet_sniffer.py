from scapy.all import sniff
from collections import deque, defaultdict, Counter
import heapq
import time
import threading
import logging


packet_queue = deque()

ip_counter = Counter()
protocol_counter = Counter()
lock = threading.Lock()


def packet_handler(pkt):
    with lock:
        packet_queue.append(pkt)


def process_packets():
    while True:
        with lock:
            while packet_queue:
                pkt = packet_queue.popleft()

                if pkt.haslayer("IP"):
                    src = pkt["IP"].src
                    dst = pkt["IP"].dst
                    proto = pkt["IP"].proto  # Protocol number

                    ip_counter[src] += 1
                    ip_counter[dst] += 1
                    protocol_counter[proto] += 1


def stats_printer():
    while True:
        time.sleep(5)
        with lock:
            total_pkt = sum(ip_counter.values())

            top_ips = heapq.nlargest(3, ip_counter.items(), key=lambda x: x[1])

            print("\n=== Packet Sniffer Stats === ")
            print(f"Total Packets: {total_pkt}")
            print("Top 3 IPs:")
            for ip, count in top_ips:
                print(f"  {ip}: {count} packets")

            print("\nProtocol Seen :")
            import socket

            # Build protocol name mapping from socket module
            proto_names = {
                getattr(socket, name): name[8:]
                for name in dir(socket)
                if name.startswith("IPPROTO_")
            }
            for proto, count in protocol_counter.items():
                name = proto_names.get(proto, str(proto))
                print(f" Protocol {name}: {count} packets")
            print("============================\n")


if __name__ == "__main__":
    threading.Thread(target=process_packets, daemon=True).start()
    threading.Thread(target=stats_printer, daemon=True).start()

    print("🚀 Starting Packet Sniffer... (Press Ctrl+C to stop)\n")
    sniff(prn=packet_handler, store=False)
