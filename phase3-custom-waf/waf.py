#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  Custom WAF — Main Reverse Proxy
#
#  Architecture:
#    Browser → [WAF :8090] → inspect → [DVWA :8888]
#                               ↓ (attack detected)
#                          [403 Block Page + Log]
#
#  Run:  python waf.py
# ─────────────────────────────────────────────────────────────

import asyncio
import aiohttp
from aiohttp import web

from config import WAF_HOST, WAF_PORT, BACKEND_URL
from engine.inspector import check_request
from engine.responder import block_response
from engine.logger import log_block


# ── Hop-by-hop headers that must not be forwarded ────────────
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade",
}


async def proxy_handler(request: web.Request) -> web.Response:
    """
    Core WAF handler:
      1. Extract request parts
      2. Inspect for attacks
      3. Block or forward
    """
    # ── Extract client IP ─────────────────────────────────────
    client_ip = request.headers.get("X-Forwarded-For", request.remote)

    # ── Read body ─────────────────────────────────────────────
    try:
        body_bytes = await request.read()
        body_str = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        body_str = ""

    # ── Inspect the request ───────────────────────────────────
    detection = check_request(
        method=request.method,
        path=request.path,
        query_string=request.query_string,
        headers=dict(request.headers),
        body=body_str,
    )

    if detection:
        # Attack detected — log and block
        await log_block(
            attacker_ip=client_ip,
            rule=detection["rule"],
            location=detection["location"],
            payload=detection["payload"],
        )
        return block_response(
            rule=detection["rule"],
            location=detection["location"],
            payload=detection["payload"],
        )

    # ── Forward clean request to backend ─────────────────────
    target_url = BACKEND_URL + request.path_qs

    # Strip hop-by-hop headers before forwarding
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP
    }
    forward_headers["X-Forwarded-For"] = client_ip
    forward_headers["X-Real-IP"] = client_ip

    try:
        async with aiohttp.ClientSession(auto_decompress=False) as session:
            async with session.request(
                method=request.method,
                url=target_url,
                headers=forward_headers,
                data=body_bytes if body_bytes else None,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as backend_resp:

                # Read backend response
                resp_body = await backend_resp.read()

                # Build response headers (strip hop-by-hop)
                resp_headers = {
                    k: v for k, v in backend_resp.headers.items()
                    if k.lower() not in HOP_BY_HOP
                }
                resp_headers["X-WAF-Protected"] = "CustomWAF/1.0"

                return web.Response(
                    status=backend_resp.status,
                    headers=resp_headers,
                    body=resp_body,
                )

    except aiohttp.ClientConnectorError:
        return web.Response(
            status=502,
            text="<h1>502 Bad Gateway</h1><p>WAF could not reach the backend. Is DVWA running on port 8888?</p>",
            content_type="text/html",
        )
    except asyncio.TimeoutError:
        return web.Response(
            status=504,
            text="<h1>504 Gateway Timeout</h1><p>Backend did not respond in time.</p>",
            content_type="text/html",
        )


# ── Startup banner ────────────────────────────────────────────
async def on_startup(app: web.Application) -> None:
    print("=" * 60)
    print("  Custom WAF — Python/aiohttp Reverse Proxy")
    print("=" * 60)
    print(f"  Listening  : http://{WAF_HOST}:{WAF_PORT}")
    print(f"  Backend    : {BACKEND_URL}")
    print(f"  Log file   : logs/waf-blocks.log")
    print(f"  Rules      : SQLi (6) + XSS (6) = 12 signatures")
    print("=" * 60)
    print("  Waiting for requests...\n")


# ── App setup ─────────────────────────────────────────────────
app = web.Application()
app.on_startup.append(on_startup)

# Route ALL methods and ALL paths through the proxy handler
app.router.add_route("*", "/{path_info:.*}", proxy_handler)

if __name__ == "__main__":
    web.run_app(app, host=WAF_HOST, port=WAF_PORT, access_log=None)