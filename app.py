import time
import threading
import heapq
import json
import psutil
import socket
import struct
import sys
import platform
from collections import deque, defaultdict, Counter
from flask import Flask, render_template, jsonify
from scapy.all import sniff, TCP, UDP, IP, Raw, get_if_list, conf
import os
import re

# Optional imports (geoip2 may not be present)
try:
    import geoip2.database

    GEOIP2_AVAILABLE = True
except Exception:
    GEOIP2_AVAILABLE = False

import requests  # fallback for GeoIP

app = Flask(__name__)

# ---------------------------
# Configuration
# ---------------------------
GEOIP_DB_PATH = "GeoLite2-City.mmdb"
BANDWIDTH_WINDOW_SECONDS = 60
BANDWIDTH_SAMPLE_RATE = 1
BANDWIDTH_HISTORY_LEN = BANDWIDTH_WINDOW_SECONDS // BANDWIDTH_SAMPLE_RATE
STATS_INTERVAL = 2
TOP_N_IPS = 10
TOP_N_PORTS = 10
TOP_N_APPS = 10
ALERT_IP_THRESHOLD = 100
ALERT_IP_WINDOW = 5
# ---------------------------

# Thread-safe structures
lock = threading.Lock()
packet_queue = deque()

# Enhanced tracking structures
ip_counter = Counter()
protocol_counter = Counter()
port_counter = Counter()
connections = set()
size_buckets = Counter()
bandwidth_history = deque(maxlen=BANDWIDTH_HISTORY_LEN)
_current_second_bytes = 0
_last_bandwidth_sample = time.time()
ip_timestamps = defaultdict(deque)
geo_cache = {}
alerts = deque(maxlen=50)
logs = deque(maxlen=200)

# New enhanced structures
traffic_flows = defaultdict(lambda: {"packets": 0, "bytes": 0, "last_seen": 0})
application_protocols = Counter()
app_bandwidth = defaultdict(lambda: {"sent": 0, "received": 0, "connections": set()})
packet_directions = {"sent": 0, "received": 0}
detailed_packets = deque(maxlen=1000)  # Store detailed packet info
network_topology = defaultdict(set)  # Graph structure for topology
process_connections = {}  # Map connections to processes

# Packet capture status
capture_status = {
    "active": False,
    "packets_captured": 0,
    "last_packet_time": 0,
    "error": None,
}

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Application layer protocol detection patterns
APP_PROTOCOLS = {
    "HTTP": [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"HTTP/1."],
    "HTTPS": [b"\x16\x03"],  # TLS handshake
    "SSH": [b"SSH-"],
    "FTP": [b"USER ", b"PASS ", b"RETR ", b"STOR "],
    "SMTP": [b"HELO ", b"EHLO ", b"MAIL FROM:", b"RCPT TO:"],
    "POP3": [b"+OK ", b"-ERR ", b"USER ", b"PASS "],
    "IMAP": [b"* OK ", b"* BAD ", b"* NO "],
    "DNS": [],  # Will be detected by port
    "DHCP": [],  # Will be detected by port
    "NTP": [],  # Will be detected by port
}

PORT_TO_PROTOCOL = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    587: "SMTP",
}

# ---- Initialize GeoIP reader once ----
geo_reader = None
if GEOIP2_AVAILABLE and os.path.exists(GEOIP_DB_PATH):
    geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)


# ---------------------------
# Logging helper
# ---------------------------
def log(msg, level="info"):
    entry = {"time": time.time(), "level": level, "msg": str(msg)}
    with lock:
        logs.appendleft(entry)
    try:
        if level == "error":
            app.logger.error(msg)
        elif level == "warn":
            app.logger.warning(msg)
        else:
            app.logger.info(msg)
    except Exception:
        print(f"[{level}] {msg}")


# ---------------------------
# System Detection and Interface Selection
# ---------------------------
def detect_system_info():
    """Detect system information and available interfaces"""
    system = platform.system()
    log(f"System detected: {system}")

    # Check if running as admin/root
    is_admin = False
    try:
        if system == "Windows":
            import ctypes

            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        else:
            is_admin = os.geteuid() == 0
    except Exception as e:
        log(f"Could not check admin privileges: {e}", "warn")

    log(f"Running with admin/root privileges: {is_admin}")

    # Get network interfaces
    try:
        interfaces = get_if_list()
        log(f"Available network interfaces: {interfaces}")

        # Filter out loopback and select best interface
        filtered_interfaces = [
            iface
            for iface in interfaces
            if not iface.startswith(("lo", "Loopback", "Software Loopback"))
        ]

        if filtered_interfaces:
            selected_interface = filtered_interfaces[0]
            log(f"Selected interface: {selected_interface}")
            return selected_interface, is_admin
        else:
            log("No suitable network interfaces found, using default", "warn")
            return None, is_admin

    except Exception as e:
        log(f"Error getting network interfaces: {e}", "error")
        return None, is_admin


# ---------------------------
# Process and Application Monitoring
# ---------------------------
def get_local_ip():
    """Get the local machine's IP address"""
    try:
        # Connect to a remote address to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        log(f"Local IP detected: {local_ip}")
        return local_ip
    except Exception as e:
        log(f"Could not detect local IP: {e}", "warn")
        return "127.0.0.1"


LOCAL_IP = get_local_ip()


def update_process_connections():
    """Update the mapping of network connections to processes"""
    global process_connections
    try:
        connections = psutil.net_connections(kind="inet")
        new_mapping = {}

        for conn in connections:
            if conn.laddr and conn.raddr:
                key = (conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port)
                try:
                    if conn.pid:
                        proc = psutil.Process(conn.pid)
                        new_mapping[key] = {
                            "pid": conn.pid,
                            "name": proc.name(),
                            "exe": proc.exe() if hasattr(proc, "exe") else "Unknown",
                        }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        process_connections = new_mapping
        log(f"Updated process connections: {len(new_mapping)} active connections")
    except Exception as e:
        log(f"Error updating process connections: {e}", "warn")


# Start process monitoring thread
def start_process_monitor():
    def monitor_loop():
        while True:
            try:
                update_process_connections()
                time.sleep(5)  # Update every 5 seconds
            except Exception as e:
                log(f"Process monitor error: {e}", "error")
                time.sleep(10)  # Wait longer on error

    threading.Thread(target=monitor_loop, daemon=True).start()
    log("Process monitor started")


# ---------------------------
# Application Layer Detection
# ---------------------------
def detect_application_protocol(pkt):
    """Detect application layer protocol from packet payload"""
    app_proto = "Unknown"

    # First try port-based detection
    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        sport = pkt.sport if hasattr(pkt, "sport") else 0
        dport = pkt.dport if hasattr(pkt, "dport") else 0

        if dport in PORT_TO_PROTOCOL:
            app_proto = PORT_TO_PROTOCOL[dport]
        elif sport in PORT_TO_PROTOCOL:
            app_proto = PORT_TO_PROTOCOL[sport]

    # Then try payload-based detection
    if pkt.haslayer(Raw) and app_proto == "Unknown":
        try:
            payload = bytes(pkt[Raw].load)
            for proto, patterns in APP_PROTOCOLS.items():
                for pattern in patterns:
                    if pattern in payload[:100]:  # Check first 100 bytes
                        app_proto = proto
                        break
                if app_proto != "Unknown":
                    break
        except Exception:
            pass  # Ignore payload parsing errors

    return app_proto


def get_process_for_connection(src_ip, src_port, dst_ip, dst_port):
    """Get process information for a network connection"""
    # Try both directions
    keys = [(src_ip, src_port, dst_ip, dst_port), (dst_ip, dst_port, src_ip, src_port)]

    for key in keys:
        if key in process_connections:
            return process_connections[key]

    return None


# ---------------------------
# GeoIP Lookup
# ---------------------------
def geoip_lookup(ip):
    if ip in geo_cache:
        return geo_cache[ip]

    if ip.startswith(("10.", "192.168.", "127.", "172.")):
        geo_cache[ip] = None
        return None

    if geo_reader:
        try:
            resp = geo_reader.city(ip)
            loc = {
                "lat": resp.location.latitude,
                "lon": resp.location.longitude,
                "country": resp.country.name,
                "city": resp.city.name or None,
            }
            geo_cache[ip] = loc
            return loc
        except Exception as e:
            log(f"GeoIP DB lookup failed for {ip}: {e}", "debug")

    geo_cache[ip] = None
    return None


# ---------------------------
# Enhanced Packet handling
# ---------------------------
def packet_handler(pkt):
    """Handle captured packets"""
    try:
        with lock:
            packet_queue.append((time.time(), pkt))
            capture_status["packets_captured"] += 1
            capture_status["last_packet_time"] = time.time()
            capture_status["active"] = True

        # Log first few packets for debugging
        if capture_status["packets_captured"] <= 5:
            log(
                f"Packet #{capture_status['packets_captured']} captured: {pkt.summary()}"
            )

    except Exception as e:
        log(f"Error in packet handler: {e}", "error")


def process_packets_loop():
    global _current_second_bytes, _last_bandwidth_sample
    log("Packet processing loop started")

    while True:
        processed_any = False
        try:
            with lock:
                while packet_queue:
                    ts, pkt = packet_queue.popleft()
                    processed_any = True

                    try:
                        pkt_len = len(pkt)
                    except Exception:
                        pkt_len = 64  # Default packet size if we can't get length

                    _current_second_bytes += pkt_len

                    if pkt.haslayer("IP") or pkt.haslayer(IP):
                        try:
                            ip_layer = pkt["IP"] if pkt.haslayer("IP") else pkt[IP]
                            src = ip_layer.src
                            dst = ip_layer.dst
                            proto = PROTO_MAP.get(ip_layer.proto, str(ip_layer.proto))

                            # Determine packet direction
                            is_outgoing = src == LOCAL_IP or src.startswith(
                                (
                                    "192.168.",
                                    "10.",
                                    "172.16.",
                                    "172.17.",
                                    "172.18.",
                                    "172.19.",
                                    "172.20.",
                                    "172.21.",
                                    "172.22.",
                                    "172.23.",
                                    "172.24.",
                                    "172.25.",
                                    "172.26.",
                                    "172.27.",
                                    "172.28.",
                                    "172.29.",
                                    "172.30.",
                                    "172.31.",
                                )
                            )
                            direction = "sent" if is_outgoing else "received"
                            packet_directions[direction] += 1

                            # Enhanced tracking
                            ip_counter[src] += 1
                            ip_counter[dst] += 1
                            protocol_counter[proto] += 1
                            connections.add((src, dst))

                            # Traffic flow analysis
                            flow_key = f"{src}:{dst}"
                            traffic_flows[flow_key]["packets"] += 1
                            traffic_flows[flow_key]["bytes"] += pkt_len
                            traffic_flows[flow_key]["last_seen"] = ts

                            # Network topology
                            network_topology[src].add(dst)

                            # Application layer detection
                            app_proto = detect_application_protocol(pkt)
                            application_protocols[app_proto] += 1

                            # Process and bandwidth tracking
                            sport, dport = None, None
                            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                                try:
                                    tcp_udp_layer = (
                                        pkt[TCP] if pkt.haslayer(TCP) else pkt[UDP]
                                    )
                                    sport = tcp_udp_layer.sport
                                    dport = tcp_udp_layer.dport

                                    port_counter[sport] += 1
                                    port_counter[dport] += 1

                                    # Get process information
                                    proc_info = get_process_for_connection(
                                        src, sport, dst, dport
                                    )
                                    app_name = (
                                        proc_info["name"]
                                        if proc_info
                                        else f"{app_proto}:{dport}"
                                    )

                                    # Update application bandwidth
                                    if is_outgoing:
                                        app_bandwidth[app_name]["sent"] += pkt_len
                                    else:
                                        app_bandwidth[app_name]["received"] += pkt_len

                                    app_bandwidth[app_name]["connections"].add(
                                        (src, dst)
                                    )
                                except Exception as e:
                                    log(f"Error processing TCP/UDP layer: {e}", "debug")

                            # Detailed packet information
                            packet_detail = {
                                "timestamp": ts,
                                "src": src,
                                "dst": dst,
                                "protocol": proto,
                                "app_protocol": app_proto,
                                "size": pkt_len,
                                "direction": direction,
                                "sport": sport,
                                "dport": dport,
                                "process": (
                                    proc_info["name"]
                                    if "proc_info" in locals() and proc_info
                                    else None
                                ),
                            }
                            detailed_packets.appendleft(packet_detail)

                            # Alert checking
                            now = ts
                            dq = ip_timestamps[src]
                            dq.append(now)
                            while dq and dq[0] < now - ALERT_IP_WINDOW:
                                dq.popleft()
                            if len(dq) >= ALERT_IP_THRESHOLD:
                                alert_msg = f"High packet rate from {src}: {len(dq)} pkts in {ALERT_IP_WINDOW}s"
                                alerts.appendleft(
                                    {
                                        "time": now,
                                        "ip": src,
                                        "count": len(dq),
                                        "msg": alert_msg,
                                        "severity": "error",
                                    }
                                )
                                log(f"ALERT: {alert_msg}", "error")

                        except Exception as e:
                            log(f"Error processing IP layer: {e}", "debug")

                    # Packet size bucketing
                    bucket = (pkt_len // 100) * 100
                    size_buckets[bucket] += 1

            # Bandwidth sampling
            now = time.time()
            if now - _last_bandwidth_sample >= 1:
                with lock:
                    bandwidth_history.append(_current_second_bytes)
                    _current_second_bytes = 0
                _last_bandwidth_sample = now

            if not processed_any:
                time.sleep(0.01)

        except Exception as e:
            log(f"Error in packet processing loop: {e}", "error")
            time.sleep(0.1)


# ---------------------------
# Enhanced Packet Sniffing
# ---------------------------
def start_sniffer():
    """Start the packet sniffer with enhanced error handling"""
    log("Starting packet sniffer...")

    # Detect system and interface
    interface, is_admin = detect_system_info()

    if not is_admin:
        log(
            "WARNING: Not running with admin/root privileges. Packet capture may fail!",
            "warn",
        )

    # Start process monitor
    start_process_monitor()

    # Start packet processing thread
    processing_thread = threading.Thread(target=process_packets_loop, daemon=True)
    processing_thread.start()
    log("Packet processing thread started")

    # Start packet capture thread
    def capture_packets():
        log("Starting packet capture thread...")
        try:
            # Try different capture methods
            capture_args = {
                "prn": packet_handler,
                "store": False,
                "count": 0,  # Capture indefinitely
            }

            # Add interface if detected
            if interface:
                capture_args["iface"] = interface
                log(f"Capturing on interface: {interface}")
            else:
                log("Capturing on default interface")

            # Set capture filter to reduce noise (optional)
            # capture_args['filter'] = "ip"  # Only IP packets

            log("Starting Scapy sniff...")
            capture_status["active"] = True
            sniff(**capture_args)

        except PermissionError:
            error_msg = "Permission denied. Please run as administrator/root."
            log(error_msg, "error")
            capture_status["error"] = error_msg
            capture_status["active"] = False

        except Exception as e:
            error_msg = f"Packet capture failed: {e}"
            log(error_msg, "error")
            capture_status["error"] = str(e)
            capture_status["active"] = False

            # Try alternative capture method
            log("Trying alternative capture method...", "warn")
            try:
                # Simplified capture without interface specification
                sniff(prn=packet_handler, store=False)
            except Exception as e2:
                log(f"Alternative capture method also failed: {e2}", "error")

    # Start capture in separate thread
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    log("Packet capture thread started")

    # Monitor capture status
    def monitor_capture():
        last_count = 0
        while True:
            time.sleep(10)  # Check every 10 seconds
            current_count = capture_status["packets_captured"]
            if current_count > last_count:
                log(f"Packet capture active: {current_count} packets captured")
                last_count = current_count
            elif not capture_status["active"]:
                log("Packet capture appears inactive", "warn")
                if capture_status.get("error"):
                    log(f"Capture error: {capture_status['error']}", "error")

    monitor_thread = threading.Thread(target=monitor_capture, daemon=True)
    monitor_thread.start()


# ---------------------------
# Flask Routes
# ---------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/status")
def status():
    """Get capture status for debugging"""
    return jsonify(capture_status)


@app.route("/data")
def data():
    # Snapshot the fast-changing structures under lock
    with lock:
        total_packets = sum(ip_counter.values())
        top_ips = heapq.nlargest(TOP_N_IPS, ip_counter.items(), key=lambda x: x[1])
        top_ports = heapq.nlargest(
            TOP_N_PORTS, port_counter.items(), key=lambda x: x[1]
        )

        sizes = sorted(
            (
                (f"{bucket}-{bucket+99}", count)
                for bucket, count in size_buckets.items()
            ),
            key=lambda x: int(x[0].split("-")[0]),
        )

        bandwidth = list(bandwidth_history)
        protocols = dict(protocol_counter)
        active_connections = len(connections)
        alerts_list = list(alerts)[:8]
        logs_list = list(logs)[:50]

        # Enhanced data
        app_protocols = dict(application_protocols)
        packet_dirs = dict(packet_directions)
        detailed_pkts = list(detailed_packets)[:100]  # Latest 100 packets

        # Traffic flows (top flows by packet count)
        top_flows = heapq.nlargest(
            20,
            [(k, v["packets"], v["bytes"]) for k, v in traffic_flows.items()],
            key=lambda x: x[1],
        )

        # Application bandwidth (convert sets to counts for JSON serialization)
        app_bw = {}
        for app, data in list(app_bandwidth.items())[:TOP_N_APPS]:
            app_bw[app] = {
                "sent": data["sent"],
                "received": data["received"],
                "total": data["sent"] + data["received"],
                "connections": len(data["connections"]),
            }

        # Network topology (convert to format suitable for visualization)
        topology_data = []
        for src, destinations in network_topology.items():
            for dst in destinations:
                topology_data.append({"source": src, "target": dst})

    # Build geo_points from top_ips (do lookups without holding the main lock)
    geo_points = []
    for ip, cnt in top_ips:
        try:
            loc = geoip_lookup(ip)
        except Exception as e:
            log(f"geoip_lookup error for {ip}: {e}", "debug")
            loc = None

        if not loc:
            continue

        lat_raw = loc.get("lat")
        lon_raw = loc.get("lon")
        if lat_raw is None or lon_raw is None:
            continue
        try:
            lat = float(lat_raw)
            lon = float(lon_raw)
        except (TypeError, ValueError):
            continue

        geo_points.append(
            {
                "ip": ip,
                "lat": lat,
                "lon": lon,
                "country": loc.get("country"),
                "city": loc.get("city"),
                "count": cnt,
            }
        )

    return jsonify(
        {
            "total_packets": total_packets,
            "packet_directions": packet_dirs,
            "top_ips": top_ips,
            "protocols": protocols,
            "app_protocols": app_protocols,
            "top_ports": top_ports,
            "packet_sizes": sizes,
            "active_connections": active_connections,
            "bandwidth": bandwidth,
            "alerts": alerts_list,
            "geo_points": geo_points,
            "logs": logs_list,
            "traffic_flows": top_flows,
            "app_bandwidth": app_bw,
            "detailed_packets": detailed_pkts,
            "network_topology": topology_data[:100],  # Limit for performance
            "capture_status": capture_status,  # Include capture status for debugging
        }
    )


# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    log("Starting Enhanced Packet Sniffer + Visualizer")
    print("=" * 60)
    print("Enhanced Network Packet Sniffer")
    print("=" * 60)
    print("IMPORTANT NOTES:")
    print("1. Run as Administrator (Windows) or Root (Linux/Mac)")
    print("2. Some antivirus software may block packet capture")
    print("3. Windows may require WinPcap or Npcap installed")
    print("4. Check /status endpoint for capture status")
    print("=" * 60)
    print(f"Local IP detected: {LOCAL_IP}")
    print(f"System: {platform.system()}")
    print("Starting services...")

    start_sniffer()
    app.run(
        debug=False, host="0.0.0.0", port=5000
    )  # Changed debug to False for production
