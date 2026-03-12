from scapy.all import sniff, IP, IPv6, TCP, UDP
import time
import stats
from collections import defaultdict, deque
from mitigator import block_ip
from config import MITIGATION_ENABLED
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ---------- CONFIG ----------
WINDOW_SECONDS = 1
BASELINE_WINDOW = 30

PPS_SPIKE_MULTIPLIER = 3
MAX_PPS_TOTAL = 5000 #20000

MAX_SYN_PER_SEC_PER_IP = 100 #200
MAX_UDP_PER_SEC_PER_IP = 200 #500

# Limit memory usage - keep only top sources
MAX_TRACKED_IPS = 1000
# ----------------------------

baseline_pps_history = deque(maxlen=BASELINE_WINDOW)
target_count_per_ip = defaultdict(int)
syn_count_per_ip = defaultdict(int)
udp_count_per_ip = defaultdict(int)

current_window_start = time.time()
window_packet_count = 0
window_byte_count = 0


def get_src_ip(packet):
    """Extract source IP from packet (IPv4 or IPv6)."""
    try:
        if IP in packet:
            return packet[IP].src
        if IPv6 in packet:
            return packet[IPv6].src
    except Exception as e:
        logger.debug(f"Error extracting source IP: {e}")
    return None


def update_top_sources(src_ip):
    """Update top sources tracking with memory limit."""
    if not src_ip:
        return

    stats.top_sources[src_ip] = stats.top_sources.get(src_ip, 0) + 1

    # Prevent unbounded growth - keep only top N
    if len(stats.top_sources) > MAX_TRACKED_IPS:
        # Remove lowest frequency entries
        sorted_sources = sorted(stats.top_sources.items(), key=lambda x: x[1], reverse=True)
        stats.top_sources = dict(sorted_sources[:MAX_TRACKED_IPS])


def reset_window_counters():
    """Reset per-window counters to prevent unbounded memory growth."""
    global syn_count_per_ip, udp_count_per_ip, target_count_per_ip
    
    # Keep only top offenders to prevent memory leak
    if len(syn_count_per_ip) > MAX_TRACKED_IPS:
        syn_count_per_ip = defaultdict(int, dict(sorted(syn_count_per_ip.items(), 
                                                        key=lambda x: x[1], reverse=True)[:MAX_TRACKED_IPS//2]))
    if len(udp_count_per_ip) > MAX_TRACKED_IPS:
        udp_count_per_ip = defaultdict(int, dict(sorted(udp_count_per_ip.items(), 
                                                        key=lambda x: x[1], reverse=True)[:MAX_TRACKED_IPS//2]))
    
    # Reset target tracking every window
    target_count_per_ip = defaultdict(int)


def analyze_window():
    """Analyze the current time window for attacks."""
    global window_packet_count, window_byte_count

    # Update stats safely
    with stats.lock:
        stats.pps = window_packet_count
        stats.bps = window_byte_count * 8

    baseline_pps_history.append(stats.pps)
    baseline = sum(baseline_pps_history) / max(1, len(baseline_pps_history))

    stats.attack_status = "SAFE"
    stats.last_alert = ""

    try:
        # 1) Total PPS too high
        if stats.pps > MAX_PPS_TOTAL * 2:
            stats.attack_status = "CRITICAL"
            stats.last_alert = f"CRITICAL: {stats.pps} packets/sec (max: {MAX_PPS_TOTAL*2})"
            try:
                stats.log_active_attack("CRITICAL_PPS", stats.last_alert)
            except Exception:
                pass
        elif stats.pps > MAX_PPS_TOTAL:
            stats.attack_status = "WARNING"
            stats.last_alert = f"High traffic: {stats.pps} packets/sec"
            try:
                stats.log_active_attack("HIGH_PPS", stats.last_alert)
            except Exception:
                pass

        # 2) Spike detection
        if len(baseline_pps_history) >= BASELINE_WINDOW and baseline > 0:
            if stats.pps > baseline * PPS_SPIKE_MULTIPLIER:
                stats.attack_status = "ATTACK"
                stats.last_alert = f"Traffic spike detected ({stats.pps}pps, baseline {int(baseline)}pps)"

                with stats.lock:
                    if len(stats.unique_ips) < 10:
                        stats.dos_alerts += 1
                    else:
                        stats.ddos_alerts += 1

                    try:
                        stats.log_active_attack("SPIKE", stats.last_alert)
                    except Exception:
                        pass

        # 3) SYN flood per IP
        for ip, syns in syn_count_per_ip.items():
            if syns >= MAX_SYN_PER_SEC_PER_IP:
                stats.attack_status = "ATTACK"
                stats.last_alert = f"SYN flood from {ip} ({syns} SYN/sec)"
                with stats.lock:
                    stats.dos_alerts += 1

                if MITIGATION_ENABLED:
                    block_ip(ip)
                try:
                    stats.log_active_attack("SYN_FLOOD", stats.last_alert, sources=[ip])
                except Exception:
                    pass
                break

        # 4) UDP flood per IP
        for ip, udps in udp_count_per_ip.items():
            if udps >= MAX_UDP_PER_SEC_PER_IP:
                stats.attack_status = "ATTACK"
                stats.last_alert = f"UDP flood from {ip} ({udps} UDP/sec)"
                with stats.lock:
                    stats.dos_alerts += 1

                if MITIGATION_ENABLED:
                    block_ip(ip)
                try:
                    stats.log_active_attack("UDP_FLOOD", stats.last_alert, sources=[ip])
                except Exception:
                    pass
                break

        # 5) DDoS detection (many IPs attacking same target)
        for target, count in target_count_per_ip.items():
            if count > 3000 and len(stats.unique_ips) > 20:
                stats.attack_status = "ATTACK"
                stats.last_alert = f"DDoS suspected on {target}"
                with stats.lock:
                    stats.ddos_alerts += 1

                if MITIGATION_ENABLED:
                    # Block top offenders
                    for ip, syns in sorted(syn_count_per_ip.items(), key=lambda x: x[1], reverse=True)[:5]:
                        if syns > 50:
                            block_ip(ip)
                try:
                    top_offenders = [ip for ip, _ in sorted(syn_count_per_ip.items(), key=lambda x: x[1], reverse=True)[:10]]
                    stats.log_active_attack("DDOS", stats.last_alert, sources=top_offenders)
                except Exception:
                    pass
                break

    except Exception as e:
        logger.error(f"Error during window analysis: {e}")


def process_packet(packet):
    """Process incoming packet for attack detection."""
    global current_window_start, window_packet_count, window_byte_count

    try:
        with stats.lock:
            stats.total_packets += 1

        window_packet_count += 1

        # Safely get packet length
        try:
            window_byte_count += len(packet)
        except Exception:
            pass

        # Extract source IP
        src_ip = get_src_ip(packet)
        
        # Track destination for DDoS detection
        if IP in packet:
            try:
                dst_ip = packet[IP].dst
                target_count_per_ip[dst_ip] += 1
            except Exception:
                pass

        # Update unique IPs and top sources
        if src_ip:
            with stats.lock:
                stats.unique_ips.add(src_ip)
                update_top_sources(src_ip)

        # Track protocol statistics
        try:
            if IP in packet:
                stats.total_ipv4 += 1
            elif IPv6 in packet:
                stats.total_ipv6 += 1
        except Exception:
            pass

        # SYN detection (only if TCP layer exists)
        if TCP in packet and src_ip:
            try:
                flags = packet[TCP].flags
                # Check for SYN (0x02) without ACK (0x10)
                if flags & 0x02 and not (flags & 0x10):
                    syn_count_per_ip[src_ip] += 1
            except Exception:
                pass

        # UDP detection
        if UDP in packet and src_ip:
            try:
                udp_count_per_ip[src_ip] += 1
            except Exception:
                pass

        # Check if time to analyze window
        now = time.time()
        if now - current_window_start >= WINDOW_SECONDS:
            analyze_window()

            current_window_start = now
            window_packet_count = 0
            window_byte_count = 0
            reset_window_counters()

    except Exception as e:
        logger.error(f"Error processing packet: {e}")


def start_capture(interface):
    """Start packet capture on specified interface."""
    try:
        logger.info(f"Starting packet capture on {interface}")
        sniff(iface=interface, prn=process_packet, store=False)
    except PermissionError:
        logger.error("Packet capture requires root privileges")
    except Exception as e:
        logger.error(f"Capture error: {e}")