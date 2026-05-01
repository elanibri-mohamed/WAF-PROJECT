# ─────────────────────────────────────────────────────────────
#  Custom WAF — Inspector
#  Extracts URI, headers, and POST body from each request
#  and runs them through the detection rules.
# ─────────────────────────────────────────────────────────────

import urllib.parse
from engine.rules import inspect


# Headers to skip inspection (internal / safe)
_SKIP_HEADERS = {
    "host", "content-length", "content-type",
    "accept", "accept-encoding", "accept-language",
    "connection", "cache-control", "pragma",
    "upgrade-insecure-requests", "sec-fetch-site",
    "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
}


def _decode(value: str) -> str:
    """URL-decode a value to catch encoded payloads like %3Cscript%3E."""
    try:
        return urllib.parse.unquote_plus(value)
    except Exception:
        return value


def check_request(method: str, path: str, query_string: str,
                  headers: dict, body: str) -> dict | None:
    """
    Inspect all parts of an HTTP request.

    Returns a result dict if an attack is found:
        {
            "rule":    { id, name, category, pattern },
            "location": "URI" | "HEADER:<name>" | "BODY",
            "payload":  <the matched string>
        }
    Returns None if the request is clean.
    """

    # ── 1. URI (path + query string) ─────────────────────────
    full_uri = path
    if query_string:
        full_uri += "?" + query_string

    decoded_uri = _decode(full_uri)
    rule = inspect(decoded_uri)
    if rule:
        return {"rule": rule, "location": "URI", "payload": decoded_uri}

    # ── 2. Query parameters (individually) ───────────────────
    if query_string:
        params = urllib.parse.parse_qs(query_string, keep_blank_values=True)
        for param_name, values in params.items():
            for val in values:
                decoded_val = _decode(val)
                rule = inspect(decoded_val)
                if rule:
                    return {
                        "rule": rule,
                        "location": f"QUERY_PARAM:{param_name}",
                        "payload": decoded_val,
                    }

    # ── 3. Headers ────────────────────────────────────────────
    for header_name, header_value in headers.items():
        if header_name.lower() in _SKIP_HEADERS:
            continue
        decoded_val = _decode(header_value)
        rule = inspect(decoded_val)
        if rule:
            return {
                "rule": rule,
                "location": f"HEADER:{header_name}",
                "payload": decoded_val,
            }

    # ── 4. Body (POST data) ───────────────────────────────────
    if body:
        decoded_body = _decode(body)
        rule = inspect(decoded_body)
        if rule:
            return {"rule": rule, "location": "BODY", "payload": decoded_body}

        # Also inspect individual POST fields
        try:
            fields = urllib.parse.parse_qs(body, keep_blank_values=True)
            for field_name, values in fields.items():
                for val in values:
                    decoded_val = _decode(val)
                    rule = inspect(decoded_val)
                    if rule:
                        return {
                            "rule": rule,
                            "location": f"BODY_PARAM:{field_name}",
                            "payload": decoded_val,
                        }
        except Exception:
            pass

    return None