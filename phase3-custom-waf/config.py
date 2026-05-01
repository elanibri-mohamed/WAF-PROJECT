# ─────────────────────────────────────────────────────────────
#  Custom WAF — Configuration
# ─────────────────────────────────────────────────────────────

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Port the WAF listens on
WAF_HOST = os.getenv("WAF_HOST", "0.0.0.0")
WAF_PORT = int(os.getenv("WAF_PORT", "8090"))

# Backend target (DVWA)
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8888")

# Log file path
LOG_FILE = os.getenv(
    "LOG_FILE",
    os.path.join(BASE_DIR, "logs", "waf-blocks.log"),
)

# Block page path
BLOCK_PAGE = os.getenv(
    "BLOCK_PAGE",
    os.path.join(BASE_DIR, "block_page.html"),
)