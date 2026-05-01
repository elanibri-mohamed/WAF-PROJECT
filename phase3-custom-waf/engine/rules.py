# ─────────────────────────────────────────────────────────────
#  Custom WAF — Detection Rules (Regex Signatures)
#  Covers SQLi and XSS payloads across URI, headers, and body.
# ─────────────────────────────────────────────────────────────

import re

# Each rule is a dict:
#   id       → unique rule identifier
#   name     → human-readable label (written to log)
#   category → "sqli" | "xss"
#   pattern  → compiled regex
#   flags    → re flags used

RULES = [
    # ── SQL Injection ─────────────────────────────────────────

    {
        "id": "SQLI-001",
        "name": "UNION SELECT statement",
        "category": "sqli",
        "pattern": re.compile(r"UNION\s+SELECT", re.IGNORECASE),
    },
    {
        "id": "SQLI-002",
        "name": "Boolean tautology (OR 1=1 variants)",
        "category": "sqli",
        "pattern": re.compile(r"'\s*OR\s*'?[\d]|'\s*OR\s*'[a-z]+'='[a-z]+", re.IGNORECASE),
    },
    {
        "id": "SQLI-003",
        "name": "SQL comment sequences",
        "category": "sqli",
        "pattern": re.compile(r"(--|#|/\*)", re.IGNORECASE),
    },
    {
        "id": "SQLI-004",
        "name": "SLEEP/BENCHMARK (blind SQLi)",
        "category": "sqli",
        "pattern": re.compile(r"(SLEEP\s*\(|BENCHMARK\s*\()", re.IGNORECASE),
    },
    {
        "id": "SQLI-005",
        "name": "Common SQL keywords",
        "category": "sqli",
        "pattern": re.compile(
            r"\b(DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+\w+\s+SET|EXEC\s*\(|EXECUTE\s*\(|xp_cmdshell)\b",
            re.IGNORECASE,
        ),
    },
    {
        "id": "SQLI-006",
        "name": "SQL quote manipulation",
        "category": "sqli",
        "pattern": re.compile(r"'\s*(;|--|OR|AND|UNION)", re.IGNORECASE),
    },

    # ── Cross-Site Scripting ──────────────────────────────────

    {
        "id": "XSS-001",
        "name": "Script tag",
        "category": "xss",
        "pattern": re.compile(r"<\s*script[\s>]", re.IGNORECASE),
    },
    {
        "id": "XSS-002",
        "name": "Event handler attributes (onerror, onload, etc.)",
        "category": "xss",
        "pattern": re.compile(r"\bon\w+\s*=", re.IGNORECASE),
    },
    {
        "id": "XSS-003",
        "name": "javascript: URI scheme",
        "category": "xss",
        "pattern": re.compile(r"javascript\s*:", re.IGNORECASE),
    },
    {
        "id": "XSS-004",
        "name": "SVG/IMG injection vectors",
        "category": "xss",
        "pattern": re.compile(r"<\s*(svg|img|iframe|object|embed)[\s>]", re.IGNORECASE),
    },
    {
        "id": "XSS-005",
        "name": "document/window object access",
        "category": "xss",
        "pattern": re.compile(r"\b(document\.|window\.|alert\s*\(|confirm\s*\(|prompt\s*\()", re.IGNORECASE),
    },
    {
        "id": "XSS-006",
        "name": "HTML entity / encoded XSS",
        "category": "xss",
        "pattern": re.compile(r"&#x?[0-9a-f]+;", re.IGNORECASE),
    },
]


def inspect(value: str) -> dict | None:
    """
    Run all rules against a string value.
    Returns the first matching rule dict, or None if clean.
    """
    for rule in RULES:
        if rule["pattern"].search(value):
            return rule
    return None