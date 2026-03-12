import threading
from collections import defaultdict

# Thread-safe lock for all shared state
lock = threading.Lock()

# Packet statistics
total_packets = 0
total_ipv4 = 0
total_ipv6 = 0

# IP tracking
unique_ips = set()

# Traffic metrics
pps = 0  # Packets per second
bps = 0  # Bytes per second

# Alert counters
dos_alerts = 0
ddos_alerts = 0

# Traffic source tracking
top_sources = {}

# Attack status
attack_status = "SAFE"
last_alert = ""

# Active attacks tracking
# Keyed by an auto-incrementing id (int) -> {type, message, sources, start_time, last_update}
active_attacks = {}
_active_attack_next_id = 1

# Blocked IPs set
blocked_ips = set()


def get_stats_copy():
    """Get a thread-safe copy of all stats."""
    with lock:
        return {
            "total_packets": total_packets,
            "total_ipv4": total_ipv4,
            "total_ipv6": total_ipv6,
            "unique_ips": len(unique_ips),
            "pps": pps,
            "bps": bps,
            "dos_alerts": dos_alerts,
            "ddos_alerts": ddos_alerts,
            "top_sources": dict(top_sources),
            "attack_status": attack_status,
            "last_alert": last_alert,
            "blocked_ips": set(blocked_ips)
        }


def reset_alerts():
    """Reset alert counters (for periodic reset if needed)."""
    global dos_alerts, ddos_alerts
    with lock:
        dos_alerts = 0
        ddos_alerts = 0


def log_active_attack(attack_type, message, sources=None):
    """Record an active attack entry and append to alerts.log.

    attack_type: short string like 'SYN_FLOOD', 'UDP_FLOOD', 'DDoS', 'SPIKE'
    message: human readable message
    sources: optional list of offending IPs or targets
    """
    global _active_attack_next_id
    try:
        import time, json
        with lock:
            attack_id = _active_attack_next_id
            _active_attack_next_id += 1

            entry = {
                "id": attack_id,
                "type": attack_type,
                "message": message,
                "sources": list(sources) if sources else [],
                "start_time": time.time(),
                "last_update": time.time(),
                "pps": pps,
                "unique_ips": len(unique_ips)
            }

            active_attacks[attack_id] = entry

        # Append to alerts log file
        try:
            with open("logs/alerts.log", "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            # Best-effort logging; don't raise
            pass

        return attack_id
    except Exception:
        return None


def get_active_attacks():
    """Return a shallow copy of active attacks dict."""
    with lock:
        return dict(active_attacks)


def clear_active_attack(attack_id):
    """Remove an active attack by id."""
    with lock:
        if attack_id in active_attacks:
            del active_attacks[attack_id]
            return True
    return False


def clear_all_active_attacks():
    """Clear all active attacks."""
    with lock:
        active_attacks.clear()