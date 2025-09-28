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
# Windows Firewall Workaround
# ---------------------------
def create_windows_firewall_rule():
    """Create Windows Firewall rule for Python packet capture"""
    if platform.system() != "Windows":
        return True

    try:
        import subprocess
        import sys

        # Get Python executable path
        python_exe = sys.executable

        # Create inbound rule
        cmd_in = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=Python Packet Sniffer Inbound",
            "dir=in",
            "action=allow",
            f"program={python_exe}",
            "enable=yes",
        ]

        # Create outbound rule
        cmd_out = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=Python Packet Sniffer Outbound",
            "dir=out",
            "action=allow",
            f"program={python_exe}",
            "enable=yes",
        ]

        # Try to create rules
        result_in = subprocess.run(cmd_in, capture_output=True, text=True)
        result_out = subprocess.run(cmd_out, capture_output=True, text=True)

        if result_in.returncode == 0 and result_out.returncode == 0:
            log("Windows Firewall rules created successfully")
            return True
        else:
            log("Failed to create Windows Firewall rules (may already exist)", "warn")
            return True  # Don't fail if rules already exist

    except Exception as e:
        log(f"Could not create firewall rules: {e}", "warn")
        return True  # Don't fail the app if firewall rules can't be created


def check_windows_capture_requirements():
    """Check and fix Windows-specific requirements"""
    if platform.system() != "Windows":
        return True

    log("Checking Windows packet capture requirements...")

    # Check if Npcap service is running
    try:
        import subprocess

        result = subprocess.run(
            ["sc", "query", "npf"], capture_output=True, text=True, shell=True
        )
        if result.returncode == 0 and "RUNNING" in result.stdout:
            log("NPF service is running")
        else:
            log("Attempting to start NPF service...", "warn")
            start_result = subprocess.run(
                ["net", "start", "npf"], capture_output=True, text=True, shell=True
            )
            if start_result.returncode == 0:
                log("NPF service started successfully")
            else:
                log("Could not start NPF service - packet capture may fail", "error")
    except Exception as e:
        log(f"Error checking NPF service: {e}", "warn")

    # Try to create firewall rules
    create_windows_firewall_rule()

    return True


# ---------------------------
# Enhanced Interface Detection and Selection
# ---------------------------
def get_detailed_interfaces():
    """Get detailed information about network interfaces"""
    interfaces_info = []

    try:
        from scapy.all import get_if_list, get_if_addr, get_if_hwaddr
        import psutil

        scapy_interfaces = get_if_list()
        psutil_interfaces = psutil.net_if_addrs()

        for iface in scapy_interfaces:
            info = {
                "name": iface,
                "description": iface,
                "ip": "Unknown",
                "mac": "Unknown",
                "active": False,
                "type": "Unknown",
            }

            # Get IP address
            try:
                info["ip"] = get_if_addr(iface)
            except:
                pass

            # Get MAC address
            try:
                info["mac"] = get_if_hwaddr(iface)
            except:
                pass

            # Get additional info from psutil
            if iface in psutil_interfaces:
                addrs = psutil_interfaces[iface]
                for addr in addrs:
                    if addr.family == 2:  # IPv4
                        info["ip"] = addr.address
                        info["active"] = True
                    elif addr.family == 17:  # MAC
                        info["mac"] = addr.address

            # Determine interface type
            if "loopback" in iface.lower() or "lo" in iface.lower():
                info["type"] = "Loopback"
            elif "wifi" in iface.lower() or "wlan" in iface.lower():
                info["type"] = "WiFi"
            elif "ethernet" in iface.lower() or "eth" in iface.lower():
                info["type"] = "Ethernet"
            elif "vmware" in iface.lower() or "virtualbox" in iface.lower():
                info["type"] = "Virtual"
            else:
                info["type"] = "Other"

            interfaces_info.append(info)

        # Sort by active status and type preference
        interfaces_info.sort(
            key=lambda x: (
                not x["active"],  # Active interfaces first
                x["type"] == "Loopback",  # Loopback last
                x["type"] == "Virtual",  # Virtual second to last
                x["name"],
            )
        )

    except Exception as e:
        log(f"Error getting detailed interface info: {e}", "error")
        # Fallback to basic interface list
        try:
            basic_interfaces = get_if_list()
            for iface in basic_interfaces:
                interfaces_info.append(
                    {
                        "name": iface,
                        "description": iface,
                        "ip": "Unknown",
                        "mac": "Unknown",
                        "active": True,
                        "type": "Unknown",
                    }
                )
        except:
            pass

    return interfaces_info


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

    # Windows-specific setup
    if system == "Windows":
        check_windows_capture_requirements()

    # Get detailed interface information
    interfaces_info = get_detailed_interfaces()
    log(f"Detected {len(interfaces_info)} network interfaces")

    for info in interfaces_info[:5]:  # Log first 5 interfaces
        log(f"Interface: {info['name']} ({info['type']}) - {info['ip']}")

    # Select best interface (first active non-loopback)
    selected_interface = None
    for info in interfaces_info:
        if info["active"] and info["type"] not in ["Loopback"]:
            selected_interface = info["name"]
            break

    if not selected_interface and interfaces_info:
        selected_interface = interfaces_info[0]["name"]

    log(f"Selected interface: {selected_interface}")
    return selected_interface, is_admin, interfaces_info


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
def test_packet_capture():
    """Test basic packet capture functionality"""
    log("Testing packet capture capabilities...")
    try:
        # Test 1: Check if we can import scapy properly
        from scapy.all import sniff, get_if_list, conf

        log("Scapy import successful")

        # Test 2: Check available interfaces
        interfaces = get_if_list()
        log(f"Available interfaces: {interfaces}")

        # Test 3: Try a very short capture test
        log("Testing 3-second packet capture...")
        test_packets = []

        def test_handler(pkt):
            test_packets.append(pkt)
            log(f"Test captured packet: {pkt.summary()[:50]}...")

        try:
            sniff(prn=test_handler, timeout=3, count=5, store=False)
            log(f"Test capture completed: {len(test_packets)} packets captured")
            return len(test_packets) > 0
        except Exception as e:
            log(f"Test capture failed: {e}", "error")
            return False

    except Exception as e:
        log(f"Packet capture test failed: {e}", "error")
        return False


# Global variables for interface selection
available_interfaces = []
selected_capture_interface = None
capture_thread_active = False


# ---------------------------
# Enhanced Packet Sniffing with Interface Selection
# ---------------------------
def test_packet_capture(interface=None):
    """Test basic packet capture functionality on specific interface"""
    log(f"Testing packet capture on interface: {interface or 'default'}")
    try:
        from scapy.all import sniff, get_if_list, conf

        # Test capture with specific configuration
        test_packets = []

        def test_handler(pkt):
            test_packets.append(pkt)
            log(
                f"Test captured packet on {interface or 'default'}: {pkt.summary()[:50]}..."
            )

        capture_args = {"prn": test_handler, "timeout": 3, "count": 3, "store": False}
        if interface:
            capture_args["iface"] = interface

        try:
            # Try with Windows-specific optimizations
            if platform.system() == "Windows":
                # Disable promiscuous mode for Windows compatibility
                capture_args["promisc"] = False
                # Set socket timeout for Windows
                capture_args["timeout"] = 5

            sniff(**capture_args)
            log(
                f"Test capture completed: {len(test_packets)} packets captured on {interface or 'default'}"
            )
            return len(test_packets) > 0, len(test_packets)
        except Exception as e:
            log(f"Test capture failed on {interface or 'default'}: {e}", "error")
            return False, 0

    except Exception as e:
        log(f"Packet capture test failed: {e}", "error")
        return False, 0


def start_sniffer():
    """Start the packet sniffer with enhanced error handling and interface selection"""
    global available_interfaces, selected_capture_interface

    log("Starting enhanced packet sniffer...")

    # Detect system and interfaces
    default_interface, is_admin, interfaces_info = detect_system_info()
    available_interfaces = interfaces_info
    selected_capture_interface = default_interface

    if not is_admin:
        log(
            "WARNING: Not running with admin/root privileges. Packet capture may fail!",
            "warn",
        )

    # Windows-specific warnings and tips
    if platform.system() == "Windows" and not is_admin:
        log("Windows users: Run as Administrator for best results", "warn")
        log(
            "If capture fails: 1) Install Npcap, 2) Disable Windows Defender temporarily",
            "warn",
        )

    # Start process monitor
    start_process_monitor()

    # Start packet processing thread
    processing_thread = threading.Thread(target=process_packets_loop, daemon=True)
    processing_thread.start()
    log("Packet processing thread started")

    # Start initial capture
    start_capture_on_interface(selected_capture_interface)


def start_capture_on_interface(interface_name):
    """Start packet capture on specific interface"""
    global capture_thread_active, selected_capture_interface

    # Stop existing capture
    capture_thread_active = False
    time.sleep(1)  # Give existing thread time to stop

    selected_capture_interface = interface_name
    log(f"Starting packet capture on interface: {interface_name}")

    def capture_packets():
        global capture_thread_active
        capture_thread_active = True

        # Find interface info
        interface_info = None
        for info in available_interfaces:
            if info["name"] == interface_name:
                interface_info = info
                break

        log(
            f"Capturing on: {interface_info['name'] if interface_info else 'default'} "
            f"({interface_info['type'] if interface_info else 'unknown'}) - "
            f"{interface_info['ip'] if interface_info else 'unknown IP'}"
        )

        # Prepare capture methods with Windows optimizations
        capture_methods = []

        if interface_name:
            # Method 1: Specific interface, no promiscuous mode (Windows-friendly)
            capture_methods.append(
                {
                    "method": f"Interface-specific ({interface_name}) - Windows optimized",
                    "args": {
                        "prn": packet_handler,
                        "iface": interface_name,
                        "store": False,
                        "timeout": 1,
                        "promisc": False,  # Windows compatibility
                    },
                }
            )

            # Method 2: Specific interface with promiscuous mode (Linux/Mac)
            if platform.system() != "Windows":
                capture_methods.append(
                    {
                        "method": f"Interface-specific ({interface_name}) - promiscuous",
                        "args": {
                            "prn": packet_handler,
                            "iface": interface_name,
                            "store": False,
                            "timeout": 1,
                            "promisc": True,
                        },
                    }
                )

        # Method 3: Default interface with filter
        capture_methods.append(
            {
                "method": "Default interface with IP filter",
                "args": {
                    "prn": packet_handler,
                    "filter": "ip",
                    "store": False,
                    "timeout": 1,
                    "promisc": False,
                },
            }
        )

        # Method 4: Default interface, no filter
        capture_methods.append(
            {
                "method": "Default interface, no filter",
                "args": {
                    "prn": packet_handler,
                    "store": False,
                    "timeout": 1,
                    "promisc": False,
                },
            }
        )

        # Try each method
        for i, method in enumerate(capture_methods):
            if not capture_thread_active:  # Stop if thread was deactivated
                break

            log(f"Trying capture method {i+1}: {method['method']}")
            try:
                capture_status["active"] = True
                capture_status["error"] = None

                # Continuous capture loop
                while capture_thread_active:
                    try:
                        sniff(count=10, **method["args"])  # Capture in small batches
                    except KeyboardInterrupt:
                        break
                    except Exception as inner_e:
                        if (
                            capture_thread_active
                        ):  # Only log if we're still supposed to be running
                            log(f"Capture batch failed: {inner_e}", "debug")
                        time.sleep(0.1)

                break  # If we get here, capture is working

            except PermissionError as e:
                error_msg = f"Permission denied for {method['method']}: {e}"
                log(error_msg, "error")
                capture_status["error"] = error_msg

            except OSError as e:
                error_msg = f"OS Error for {method['method']}: {e}"
                log(error_msg, "error")
                capture_status["error"] = error_msg

            except Exception as e:
                error_msg = f"Failed {method['method']}: {e}"
                log(error_msg, "warn")
                capture_status["error"] = error_msg
                continue

        # If all methods failed
        if capture_thread_active:
            log("All capture methods failed", "error")
            capture_status["active"] = False

    # Start capture in separate thread
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    log("Packet capture thread started")

    # Enhanced monitoring
    def monitor_capture():
        last_count = 0
        no_packet_warnings = 0

        while capture_thread_active:
            time.sleep(10)
            current_count = capture_status["packets_captured"]

            if current_count > last_count:
                log(f"Capture active on {interface_name}: {current_count} packets")
                last_count = current_count
                no_packet_warnings = 0
            else:
                no_packet_warnings += 1
                if no_packet_warnings == 3 and platform.system() == "Windows":
                    log("Windows users: If no packets captured, try:", "warn")
                    log(
                        "1. Temporarily disable Windows Defender Real-time protection",
                        "warn",
                    )
                    log("2. Run: ping google.com (in another terminal)", "warn")
                    log("3. Browse to websites to generate traffic", "warn")

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
    return jsonify(
        {
            **capture_status,
            "selected_interface": selected_capture_interface,
            "available_interfaces": available_interfaces[:10],  # Limit for performance
        }
    )


@app.route("/interfaces")
def get_interfaces():
    """Get available network interfaces"""
    return jsonify(
        {"interfaces": available_interfaces, "selected": selected_capture_interface}
    )


@app.route("/select_interface", methods=["POST"])
def select_interface():
    """Select network interface for packet capture"""
    try:
        from flask import request

        data = request.get_json()
        interface_name = data.get("interface")

        if interface_name == "all":
            interface_name = None  # Capture on all interfaces

        log(f"Switching to interface: {interface_name or 'all interfaces'}")
        start_capture_on_interface(interface_name)

        return jsonify(
            {
                "success": True,
                "message": f'Switched to {interface_name or "all interfaces"}',
                "selected_interface": interface_name,
            }
        )

    except Exception as e:
        log(f"Error selecting interface: {e}", "error")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/test_interface/<interface_name>")
def test_interface(interface_name):
    """Test packet capture on specific interface"""
    if interface_name == "default":
        interface_name = None

    success, packet_count = test_packet_capture(interface_name)

    return jsonify(
        {
            "success": success,
            "packets_captured": packet_count,
            "interface": interface_name or "default",
            "message": (
                f"Captured {packet_count} packets in test" if success else "Test failed"
            ),
        }
    )


@app.route("/windows_firewall_fix")
def windows_firewall_fix():
    """Attempt to fix Windows firewall issues"""
    if platform.system() != "Windows":
        return jsonify({"success": False, "error": "Not a Windows system"})

    try:
        success = create_windows_firewall_rule()
        if success:
            return jsonify(
                {
                    "success": True,
                    "message": "Windows firewall rules created. Try packet capture again.",
                }
            )
        else:
            return jsonify(
                {
                    "success": False,
                    "error": "Failed to create firewall rules. Run as Administrator.",
                }
            )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


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
