import os
import platform

# ==========================
# Network Interface
# ==========================

if platform.system() == "Windows":
    INTERFACE = None
else:
    INTERFACE = os.getenv("INTERFACE", "eth0")

# ==========================
# Mitigation Settings
# ==========================

MITIGATION_ENABLED = True
BLOCK_DURATION_SECONDS = 200 #600

# ==========================
# Detection Thresholds
# ==========================

WARNING_PPS = 100  #500
ATTACK_PPS = 300  #1000
CRITICAL_PPS = 500 #3000

ATTACK_BPS = 1_00_000 #5_000_000
DDOS_UNIQUE_IP_THRESHOLD = 30 #50

ALERT_COOLDOWN_SECONDS = 10 #30

# ==========================
# Security
# ==========================

# API_KEY = "supersecret123"

# ==========================
# Whitelist
# ==========================

WHITELIST = {
    "127.0.0.1",
    "10.0.0.0/8",
}
