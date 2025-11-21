import time
import threading
import heapq
import psutil
import socket
import platform
import webbrowser
import os
from collections import deque, defaultdict, Counter
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from scapy.all import sniff, TCP, UDP, IP, Raw, get_if_list

# ---------------------------
# Optional / System Imports
# ---------------------------
try:
    import geoip2.database
    GEOIP2_AVAILABLE = True
except Exception:
    GEOIP2_AVAILABLE = False

# ---------------------------
# Configuration & Constants
# ---------------------------
GEOIP_DB_PATH = "GeoLite2-City.mmdb"
STATS_INTERVAL = 1.0  # Broadcast updates every 1 second
TOP_N = 10
PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}
LOCAL_IP = "127.0.0.1"

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
# async_mode='threading' is the most stable for Windows + Scapy
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# ---------------------------
# Helpers (Firewall & GeoIP)
# ---------------------------
def get_local_ip():
    """Best effort to find the local IP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't actually connect, just determines routing
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def geoip_lookup(reader, cache, ip):
    """Resolves IP to location using GeoLite2."""
    if ip in cache:
        return cache[ip]
    
    # Skip private networks
    if ip.startswith(("10.", "192.168.", "127.", "172.")):
        cache[ip] = None
        return None

    if reader:
        try:
            resp = reader.city(ip)
            loc = {
                "lat": resp.location.latitude,
                "lon": resp.location.longitude,
                "country": resp.country.name,
                "city": resp.city.name,
            }
            cache[ip] = loc
            return loc
        except Exception:
            pass
            
    cache[ip] = None
    return None

def create_windows_firewall_rule():
    """Auto-adds Python to Windows Firewall to allow packet capture."""
    if platform.system() != "Windows": return
    import subprocess, sys
    python_exe = sys.executable
    try:
        # We attempt to add allow rules for the python executable
        cmds = [
            f"netsh advfirewall firewall add rule name=\"Sniffer_In\" dir=in action=allow program=\"{python_exe}\" enable=yes",
            f"netsh advfirewall firewall add rule name=\"Sniffer_Out\" dir=out action=allow program=\"{python_exe}\" enable=yes"
        ]
        for cmd in cmds:
            subprocess.run(cmd, shell=True, capture_output=True)
    except Exception as e:
        print(f"Firewall rule error: {e}")

# ---------------------------
# Core Logic Class
# ---------------------------
class NetworkAnalyzer:
    def __init__(self):
        self.lock = threading.Lock()
        self.active = False
        self.packet_queue = deque()
        
        # Stats Containers
        self.ip_counter = Counter()
        self.protocol_counter = Counter()
        self.port_counter = Counter()
        self.traffic_flows = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self.packet_directions = {"sent": 0, "received": 0}
        
        # Queues for UI (limited size to prevent memory leaks)
        self.detailed_packets = deque(maxlen=100) 
        self.alerts = deque(maxlen=20)
        self.logs = deque(maxlen=50)
        
        # Bandwidth / Charts
        self.bandwidth_history = deque(maxlen=60)
        self._current_second_bytes = 0
        
        # System
        self.process_connections = {}
        self.geo_cache = {}
        self.geo_reader = None
        
        # Load GeoIP if available
        if GEOIP2_AVAILABLE and os.path.exists(GEOIP_DB_PATH):
            try:
                self.geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
            except Exception as e:
                print(f"GeoIP Error: {e}")

        # Start Process Monitor Thread
        threading.Thread(target=self._monitor_processes, daemon=True).start()

    def log(self, msg, level="info"):
        with self.lock:
            self.logs.appendleft({"time": time.time(), "level": level, "msg": str(msg)})
        print(f"[{level.upper()}] {msg}")

    def _monitor_processes(self):
        """Background task: Maps network sockets to Process IDs (PIDs)."""
        while True:
            try:
                new_mapping = {}
                # 'inet' covers both IPv4 and IPv6
                for conn in psutil.net_connections(kind='inet'):
                    if conn.laddr and conn.pid:
                        # Create a key based on Local IP/Port
                        # We can usually identify a process just by who owns the local port
                        key = (conn.laddr.ip, conn.laddr.port)
                        try:
                            proc = psutil.Process(conn.pid)
                            new_mapping[key] = {"name": proc.name(), "pid": conn.pid}
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                            
                        # Also map 0.0.0.0 or :: to the port for generic listeners
                        if conn.laddr.ip in ['0.0.0.0', '::', '127.0.0.1']:
                            new_mapping[('0.0.0.0', conn.laddr.port)] = {"name": proc.name(), "pid": conn.pid}

                with self.lock:
                    self.process_connections = new_mapping
            except Exception: 
                pass
            time.sleep(2) # Refresh every 2 seconds

    def packet_handler(self, pkt):
        """Callback from Scapy: just put packet in queue to avoid blocking the sniffer."""
        if not self.active: return
        with self.lock:
            self.packet_queue.append((time.time(), pkt))

    def process_packet_queue(self):
        """Worker thread: Consumes raw packets and updates stats."""
        global LOCAL_IP
        while True:
            processed_any = False
            
            # Process in chunks to avoid locking for too long
            batch_size = 50
            current_batch = []

            with self.lock:
                while self.packet_queue and len(current_batch) < batch_size:
                    current_batch.append(self.packet_queue.popleft())

            if current_batch:
                processed_any = True
                
                # Process the batch without holding the lock (mostly)
                for ts, pkt in current_batch:
                    pkt_len = len(pkt)
                    
                    # We need lock to update counters
                    with self.lock:
                        self._current_second_bytes += pkt_len

                    if IP in pkt:
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                        proto_num = pkt[IP].proto
                        proto_name = PROTO_MAP.get(proto_num, str(proto_num))

                        # Identify Direction
                        # If source is us, it's Sent. Otherwise Received.
                        direction = "sent" if src == LOCAL_IP else "received"
                        
                        # Port & Process Logic
                        sport, dport = 0, 0
                        process_name = "-"
                        
                        if TCP in pkt or UDP in pkt:
                            layer = pkt[TCP] if TCP in pkt else pkt[UDP]
                            sport = layer.sport
                            dport = layer.dport
                            
                            # Determine which local port to look up
                            lookup_port = sport if direction == "sent" else dport
                            lookup_ip = src if direction == "sent" else dst
                            
                            # Try exact match
                            proc_info = self.process_connections.get((lookup_ip, lookup_port))
                            # Try generic match (0.0.0.0)
                            if not proc_info:
                                proc_info = self.process_connections.get(('0.0.0.0', lookup_port))

                            if proc_info:
                                process_name = proc_info['name']

                        with self.lock:
                            # Update Stats
                            self.ip_counter[src] += 1
                            self.ip_counter[dst] += 1
                            self.protocol_counter[proto_name] += 1
                            if dport: self.port_counter[dport] += 1
                            
                            # Flow
                            flow_key = f"{src}:{dst}"
                            self.traffic_flows[flow_key]["packets"] += 1
                            self.traffic_flows[flow_key]["bytes"] += pkt_len
                            self.packet_directions[direction] += 1

                            # Add to detailed list
                            self.detailed_packets.appendleft({
                                "timestamp": ts,
                                "src": src, "dst": dst,
                                "protocol": proto_name,
                                "size": pkt_len,
                                "direction": direction,
                                "process": process_name
                            })
            
            if not processed_any:
                time.sleep(0.05) # Sleep if no packets to save CPU

    def get_snapshot(self):
        """Returns a JSON-ready snapshot of current stats for the UI."""
        with self.lock:
            # Bandwidth management: push current second's total to history
            self.bandwidth_history.append(self._current_second_bytes)
            self._current_second_bytes = 0

            # Helper to get top N IPs
            top_ips = heapq.nlargest(TOP_N, self.ip_counter.items(), key=lambda x: x[1])
            
            # Geo Logic
            geo_points = []
            for ip, count in top_ips:
                loc = geoip_lookup(self.geo_reader, self.geo_cache, ip)
                if loc:
                    geo_points.append({**loc, "ip": ip, "count": count})

            # Top Flows
            top_flows = heapq.nlargest(10, 
                [(k, v["packets"], v["bytes"]) for k, v in self.traffic_flows.items()],
                key=lambda x: x[1])
            
            # Top Ports
            top_ports = heapq.nlargest(TOP_N, self.port_counter.items(), key=lambda x: x[1])

            return {
                "total_packets": sum(self.ip_counter.values()),
                "packet_directions": self.packet_directions,
                "top_ips": top_ips,
                "protocols": dict(self.protocol_counter),
                "top_ports": top_ports,
                "bandwidth": list(self.bandwidth_history),
                "geo_points": geo_points,
                "traffic_flows": top_flows,
                "detailed_packets": list(self.detailed_packets),
                "active": self.active
            }

# Initialize the Analyzer Global Instance
analyzer = NetworkAnalyzer()

# ---------------------------
# Background Broadcaster
# ---------------------------
def broadcast_loop():
    """Pushes data to clients via WebSocket every second."""
    while True:
        data = analyzer.get_snapshot()
        socketio.emit('stats_update', data)
        time.sleep(STATS_INTERVAL)

# ---------------------------
# Flask Routes
# ---------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/start", methods=["POST"])
def start_capture():
    json_data = request.json or {}
    iface = json_data.get("interface")
    
    if not iface:
        # Auto-select first available if none provided
        try:
            iface = list(psutil.net_if_addrs().keys())[0]
        except:
            iface = get_if_list()[0]

    if analyzer.active:
        return jsonify({"status": "already_running"})

    analyzer.active = True
    analyzer.log(f"Starting capture on {iface}")
    
    def sniffer_thread():
        try:
            # Scapy configuration
            conf_args = {
                "prn": analyzer.packet_handler, 
                "store": False,
            }
            
            if iface: 
                conf_args["iface"] = iface

            # Windows-specific optimization:
            # Promiscuous mode often crashes standard Windows WiFi drivers.
            # We disable it for stability on Windows.
            if platform.system() == "Windows":
                conf_args["promisc"] = False 
            
            sniff(**conf_args)
        except Exception as e:
            analyzer.active = False
            analyzer.log(f"Sniffer crashed: {e}", "error")
            print(f"Sniffer Error: {e}")

    t = threading.Thread(target=sniffer_thread, daemon=True)
    t.start()
    return jsonify({"status": "started", "interface": iface})

@app.route("/api/stop", methods=["POST"])
def stop_capture():
    analyzer.active = False
    analyzer.log("Capture stopped")
    return jsonify({"status": "stopped"})

@app.route("/api/interfaces")
def get_interfaces():
    """Returns friendly interface names (e.g. 'Wi-Fi') for Windows users."""
    try:
        # psutil returns friendly names
        interfaces = list(psutil.net_if_addrs().keys())
        return jsonify({"interfaces": interfaces})
    except Exception as e:
        # Fallback to Scapy's internal list
        return jsonify({"interfaces": get_if_list()})

# ---------------------------
# Main Entry Point
# ---------------------------
if __name__ == "__main__":
    # 1. Find Local IP
    LOCAL_IP = get_local_ip()
    
    # 2. Fix Windows Firewall (if needed)
    create_windows_firewall_rule()
    
    # 3. Start Background Threads
    # Thread for processing packets from queue -> stats
    threading.Thread(target=analyzer.process_packet_queue, daemon=True).start()
    # Thread for broadcasting stats -> UI
    threading.Thread(target=broadcast_loop, daemon=True).start()
    
    # 4. Launch Browser
    print("="*40)
    print(f"🚀 Dashboard running at http://127.0.0.1:5000")
    print("="*40)
    webbrowser.open("http://127.0.0.1:5000")
    
    # 5. Run Flask with SocketIO
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)