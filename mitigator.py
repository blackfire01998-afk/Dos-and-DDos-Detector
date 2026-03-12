import subprocess
import time
import threading
import ipaddress
import stats
import json
import logging
from config import WHITELIST, BLOCK_DURATION_SECONDS, MITIGATION_ENABLED

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def is_ip_whitelisted(ip):
    """Check if IP is in whitelist, supporting both individual IPs and CIDR ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for whitelist_entry in WHITELIST:
            try:
                # Try as CIDR range first (classless inter domain routing)
                if ip_obj in ipaddress.ip_network(whitelist_entry, strict=False):
                    return True
            except ValueError:
                # If not CIDR, try exact match
                if ip == whitelist_entry:
                    return True
        return False
    except ValueError:
        return False


def log_alert(message):
    """Log alert to file with proper error handling."""
    try:
        entry = {
            "timestamp": time.time(),
            "message": message,
            "pps": stats.pps,
            "unique_ips": len(stats.unique_ips)
        }
        with open("logs/alerts.log", "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.error(f"Failed to log alert: {e}")


def block_ip(ip):
    """Block an IP address using iptables (Linux only)."""
    if not MITIGATION_ENABLED:
        return False, "Mitigation disabled"

    # Validate IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False, "Invalid IP address"

    # Check whitelist
    if is_ip_whitelisted(ip):
        return False, "IP is whitelisted"

    # Check if already blocked
    with stats.lock:
        if ip in stats.blocked_ips:
            return False, "IP already blocked"

    # Block with iptables
    try:
        result = subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            timeout=5
        )

        if result.returncode != 0:
            error_msg = result.stderr.decode() if result.stderr else "Unknown error"
            logger.error(f"iptables failed for {ip}: {error_msg}")
            return False, f"iptables error: {error_msg}"

        # Add to blocked set
        with stats.lock:
            stats.blocked_ips.add(ip)

        log_alert(f"[MITIGATION] Blocked IP: {ip}")
        logger.info(f"Blocked IP: {ip}")

        # Schedule auto-unblock
        t = threading.Thread(target=auto_unblock, args=(ip,), daemon=True)
        t.start()

        return True, f"Blocked {ip}"

    except FileNotFoundError:
        return False, "iptables not found - Linux only"
    except subprocess.TimeoutExpired:
        return False, "iptables command timeout"
    except Exception as e:
        logger.error(f"Error blocking {ip}: {e}")
        return False, str(e)


def unblock_ip(ip):
    """Unblock an IP address using iptables (Linux only)."""
    try:
        result = subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            timeout=5
        )

        if result.returncode != 0:
            error_msg = result.stderr.decode() if result.stderr else "Unknown error"
            logger.error(f"iptables unblock failed for {ip}: {error_msg}")
            return False, f"iptables error: {error_msg}"

        # Remove from blocked set
        with stats.lock:
            if ip in stats.blocked_ips:
                stats.blocked_ips.remove(ip)

        log_alert(f"[MITIGATION] Unblocked IP: {ip}")
        logger.info(f"Unblocked IP: {ip}")
        return True, f"Unblocked {ip}"

    except FileNotFoundError:
        return False, "iptables not found - Linux only"
    except subprocess.TimeoutExpired:
        return False, "iptables command timeout"
    except Exception as e:
        logger.error(f"Error unblocking {ip}: {e}")
        return False, str(e)


def auto_unblock(ip):
    """Automatically unblock IP after block duration expires."""
    time.sleep(BLOCK_DURATION_SECONDS)
    with stats.lock:
        if ip in stats.blocked_ips:
            unblock_ip(ip)