from flask import Flask, jsonify, render_template, request, send_file
import threading
import os
import ipaddress
import logging
import time
import stats
from packet_capture import start_capture
from config import INTERFACE
from mitigator import block_ip, unblock_ip

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)


# Security configs
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max request size
app.config['JSON_SORT_KEYS'] = False

capture_started = False
capture_thread = None


def validate_ip(ip):
    """Validate IP address format."""
    if not ip or not isinstance(ip, str):
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/start")
def start():
    global capture_thread

    if capture_thread is None or not capture_thread.is_alive():
        capture_thread = threading.Thread(
            target=start_capture,
            args=(INTERFACE,),
            daemon=True
        )
        capture_thread.start()
        logger.info("Packet capture started")

    return jsonify({"status": "Capture started"}), 200


@app.route("/api/stats")

def api_stats():
    try:
        with stats.lock:
            top = sorted(stats.top_sources.items(), key=lambda x: x[1], reverse=True)[:10]

        # Include active attacks for live logging in the dashboard
        active = stats.get_active_attacks()
        # Return as list of entries for JSON serialization
        active_list = list(active.values())

        return jsonify({
            "total_packets": stats.total_packets,
            "unique_ips": len(stats.unique_ips),
            "pps": stats.pps,
            "bps": stats.bps,
            "dos_alerts": stats.dos_alerts,
            "ddos_alerts": stats.ddos_alerts,
            "attack_status": stats.attack_status,
            "last_alert": stats.last_alert,
            "top_sources": top,
            "blocked_ips": list(stats.blocked_ips),
            "active_attacks": active_list
        })
    except Exception as e:
        logger.error(f"Error in /api/stats: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/block", methods=["POST"])

def api_block():
    try:
        # Try to get JSON body; if Flask didn't parse it, fall back to raw data
        data = request.get_json(silent=True)
        if data is None:
            logger.info(f"Raw request headers: {dict(request.headers)}")
            raw = request.get_data(as_text=True)
            logger.info(f"Raw request body: {raw}")
            try:
                import json
                data = json.loads(raw) if raw else None
            except Exception:
                data = None

        if not data:
            return jsonify({"success": False, "message": "No JSON data provided"}), 400

        ip = data.get("ip")

        # Validate IP format
        if not validate_ip(ip):
            return jsonify({"success": False, "message": "Invalid IP address format"}), 400

        # Check if trying to block self
        if ip == request.remote_addr:
            return jsonify({"success": False, "message": "Cannot block yourself"}), 403

        # Block the IP
        ok, msg = block_ip(ip)
        status_code = 200 if ok else 400
        return jsonify({"success": ok, "message": msg}), status_code

    except Exception as e:
        logger.error(f"Error in /api/block: {e}")
        return jsonify({"success": False, "message": "Internal server error"}), 500


@app.route("/api/unblock", methods=["POST"])

def api_unblock():
    try:
        data = request.get_json(silent=True)
        if data is None:
            logger.info(f"Raw request headers: {dict(request.headers)}")
            raw = request.get_data(as_text=True)
            logger.info(f"Raw request body: {raw}")
            try:
                import json
                data = json.loads(raw) if raw else None
            except Exception:
                data = None

        if not data:
            return jsonify({"success": False, "message": "No JSON data provided"}), 400

        ip = data.get("ip")

        # Validate IP format
        if not validate_ip(ip):
            return jsonify({"success": False, "message": "Invalid IP address format"}), 400

        # Unblock the IP
        ok, msg = unblock_ip(ip)
        status_code = 200 if ok else 400
        return jsonify({"success": ok, "message": msg}), status_code

    except Exception as e:
        logger.error(f"Error in /api/unblock: {e}")
        return jsonify({"success": False, "message": "Internal server error"}), 500


@app.route('/favicon.ico')
def favicon():
    # Return no content for favicon requests to avoid 404 in the browser console
    return ('', 204)


@app.route("/download_logs")

def download_logs():
    try:
        path = "logs/alerts.log"
        if not os.path.exists(path):
            return jsonify({"error": "No logs found"}), 404
        return send_file(path, as_attachment=True, download_name="alerts.log")
    except Exception as e:
        logger.error(f"Error downloading logs: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/health")
def health():
    return jsonify({"status": "running", "timestamp": time.time()}), 200


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Rate limit exceeded: {e.description}")
    return jsonify({"error": "Too many requests"}), 429


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    logger.info("Starting DDoS/DoS Detection Dashboard on 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)