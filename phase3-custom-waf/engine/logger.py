# ─────────────────────────────────────────────────────────────
#  Custom WAF — Logger
#  Writes blocked request events to a local log file.
#
#  Log format (pipe-delimited):
#  TIMESTAMP | ATTACKER_IP | RULE_ID | RULE_NAME | LOCATION | PAYLOAD
# ─────────────────────────────────────────────────────────────

import os
import asyncio
from datetime import datetime, timezone
from config import LOG_FILE

# Ensure log directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Async lock to prevent concurrent writes corrupting the log
_lock = asyncio.Lock()


async def log_block(attacker_ip: str, rule: dict, location: str, payload: str) -> None:
    """
    Append a blocked request entry to the WAF log file.

    Fields:
        timestamp    → ISO-8601 UTC
        attacker_ip  → client IP address
        rule_id      → e.g. SQLI-001
        rule_name    → human-readable rule name
        location     → where the payload was found (URI / HEADER / BODY)
        payload      → the raw malicious string (truncated to 200 chars)
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    safe_payload = payload.replace("\n", " ").replace("\r", " ")[:200]

    line = (
        f"{timestamp} | "
        f"{attacker_ip} | "
        f"{rule['id']} | "
        f"{rule['name']} | "
        f"{location} | "
        f"{safe_payload}\n"
    )

    async with _lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)

    # Also echo to stdout for live monitoring
    print(f"[BLOCKED] {timestamp} | {attacker_ip} | {rule['id']} | {location} | {safe_payload}")