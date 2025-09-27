import time
import threading
import heapq
import json
from collections import deque, defaultdict, Counter
from flask import Flask, render_template, jsonify
from scapy.all import sniff
import os

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
ALERT_IP_THRESHOLD = 100
ALERT_IP_WINDOW = 5
# ---------------------------

# Thread-safe structures
lock = threading.Lock()
packet_queue = deque()

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
logs = deque(maxlen=200)  # <-- our live logger buffer

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

# ---- Initialize GeoIP reader once ----
geo_reader = None
if GEOIP2_AVAILABLE and os.path.exists(GEOIP_DB_PATH):
    geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)


# ---------------------------
# Logging helper
# ---------------------------
def log(msg, level="info"):
    entry = {"time": time.time(), "level": level, "msg": str(msg)}
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
        log(f"Skipping private IP {ip}", "debug")
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
            log(f"GeoIP DB {ip} → {loc}")
            geo_cache[ip] = loc
            return loc
        except Exception as e:
            log(f"GeoIP DB lookup failed for {ip}: {e}", "warn")

    log(f"No location for {ip}", "debug")
    geo_cache[ip] = None
    return None


# ---------------------------
# Packet handling
# ---------------------------
def packet_handler(pkt):
    with lock:
        packet_queue.append((time.time(), pkt))


def process_packets_loop():
    global _current_second_bytes, _last_bandwidth_sample

    while True:
        processed_any = False
        with lock:
            while packet_queue:
                ts, pkt = packet_queue.popleft()
                processed_any = True

                try:
                    pkt_len = len(pkt)
                except Exception:
                    pkt_len = 0
                _current_second_bytes += pkt_len

                if pkt.haslayer("IP"):
                    src = pkt["IP"].src
                    dst = pkt["IP"].dst
                    proto = PROTO_MAP.get(pkt["IP"].proto, str(pkt["IP"].proto))

                    ip_counter[src] += 1
                    ip_counter[dst] += 1
                    protocol_counter[proto] += 1
                    connections.add((src, dst))

                    now = ts
                    dq = ip_timestamps[src]
                    dq.append(now)
                    while dq and dq[0] < now - ALERT_IP_WINDOW:
                        dq.popleft()
                    if len(dq) >= ALERT_IP_THRESHOLD:
                        alerts.appendleft(
                            {
                                "time": now,
                                "ip": src,
                                "count": len(dq),
                                "msg": f"High packet rate from {src}: {len(dq)} pkts in {ALERT_IP_WINDOW}s",
                            }
                        )
                        log(f"ALERT: High packet rate from {src}", "error")

                if pkt.haslayer("TCP") or pkt.haslayer("UDP"):
                    try:
                        sport = pkt.sport
                        dport = pkt.dport
                        port_counter[sport] += 1
                        port_counter[dport] += 1
                    except Exception:
                        pass

                bucket = (pkt_len // 100) * 100
                size_buckets[bucket] += 1

        now = time.time()
        if now - _last_bandwidth_sample >= 1:
            with lock:
                bandwidth_history.append(_current_second_bytes)
                _current_second_bytes = 0
            _last_bandwidth_sample = now

        if not processed_any:
            time.sleep(0.01)


# ---------------------------
# Start sniffing
# ---------------------------
def start_sniffer():
    threading.Thread(target=process_packets_loop, daemon=True).start()
    threading.Thread(
        target=lambda: sniff(prn=packet_handler, store=False), daemon=True
    ).start()


# ---------------------------
# Flask Routes
# ---------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/data")
def data():
    # Snapshot the fast-changing structures under lock, then perform GeoIP lookups
    # outside the lock to avoid blocking packet processing.
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

    # Build geo_points from top_ips (do lookups without holding the main lock)
    geo_points = []
    for ip, cnt in top_ips:
        try:
            loc = geoip_lookup(ip)
        except Exception as e:
            log(f"geoip_lookup error for {ip}: {e}", "warn")
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
            "top_ips": top_ips,
            "protocols": protocols,
            "top_ports": top_ports,
            "packet_sizes": sizes,
            "active_connections": active_connections,
            "bandwidth": bandwidth,
            "alerts": alerts_list,
            "geo_points": geo_points,
            "logs": logs_list,
        }
    )


# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    log("Starting Packet Sniffer + Visualizer")
    print("NOTE: Run as root/admin for packet capture")
    start_sniffer()
    app.run(debug=True)
