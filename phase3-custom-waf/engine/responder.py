# ─────────────────────────────────────────────────────────────
#  Custom WAF — Responder
#  Reads the block_page.html template and returns it as a
#  403 Forbidden aiohttp response.
# ─────────────────────────────────────────────────────────────

import os
from aiohttp import web
from config import BLOCK_PAGE


def _load_block_page() -> str:
    path = os.path.join(os.path.dirname(__file__), "..", BLOCK_PAGE)
    with open(os.path.abspath(path), "r", encoding="utf-8") as f:
        return f.read()


def block_response(rule: dict, location: str, payload: str) -> web.Response:
    """Return a 403 response with the custom block HTML page."""
    html = _load_block_page()

    # Inject rule info into the page (safe — these are our own rule strings)
    html = html.replace("{{RULE_ID}}", rule["id"])
    html = html.replace("{{RULE_NAME}}", rule["name"])
    html = html.replace("{{LOCATION}}", location)

    return web.Response(
        status=403,
        content_type="text/html",
        text=html,
        headers={
            "X-WAF-Blocked": "true",
            "X-WAF-Rule": rule["id"],
        },
    )