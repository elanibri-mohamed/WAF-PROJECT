import re

RULES = [
    # ═══════════════════════════════════════════════════════════
    # 1. SQL INJECTION (6 règles)
    # ═══════════════════════════════════════════════════════════
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
        "name": "Dangerous SQL keywords",
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

    # ═══════════════════════════════════════════════════════════
    # 2. CROSS-SITE SCRIPTING (6 règles)
    # ═══════════════════════════════════════════════════════════
    {
        "id": "XSS-001",
        "name": "Script tag",
        "category": "xss",
        "pattern": re.compile(r"<\s*script[\s>]", re.IGNORECASE),
    },
    {
        "id": "XSS-002",
        "name": "Event handler attributes",
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
        "name": "SVG/IMG/IFRAME injection vectors",
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

    # ═══════════════════════════════════════════════════════════
    # 3. COMMAND INJECTION — 4 règles (CORRIGÉ : plus de FP)
    # ═══════════════════════════════════════════════════════════
    {
        "id": "CMDI-001",
        "name": "Command separator with shell command",
        "category": "cmdi",
        # Ne matche que si un séparateur est suivi d'une commande shell
        "pattern": re.compile(r"[;&|`]\s*(?:ls|cat|whoami|id|pwd|echo|ping|nc|wget|curl|bash|sh|cmd|powershell|python|perl|ruby|uname|ifconfig|ipconfig|netstat|ps|kill|rm|mv|cp|chmod|chown)\b", re.IGNORECASE),
    },
    {
        "id": "CMDI-002",
        "name": "Command substitution $() or backticks",
        "category": "cmdi",
        "pattern": re.compile(r"\$\s*\(|`[^`]+`", re.IGNORECASE),
    },
    {
        "id": "CMDI-003",
        "name": "Shell execution functions",
        "category": "cmdi",
        "pattern": re.compile(r"\b(system|exec|shell_exec|passthru|popen|proc_open|eval)\s*\(", re.IGNORECASE),
    },
    {
        "id": "CMDI-004",
        "name": "Dangerous system commands",
        "category": "cmdi",
        "pattern": re.compile(r"\b(cat\s+/etc|ls\s+-|whoami|id\s*;|ping\s+-c|nc\s+-|wget\s+|curl\s+|uname\s+-)\b", re.IGNORECASE),
    },

    # ═══════════════════════════════════════════════════════════
    # 4. FILE INCLUSION / PATH TRAVERSAL (DVWA File Inclusion) — 4 règles
    # ═══════════════════════════════════════════════════════════
    {
        "id": "LFI-001",
        "name": "Path traversal sequences",
        "category": "lfi",
        "pattern": re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)", re.IGNORECASE),
    },
    {
        "id": "LFI-002",
        "name": "PHP wrappers (file://, php://, data://, expect://)",
        "category": "lfi",
        "pattern": re.compile(r"(file|php|data|expect|zip|phar)://", re.IGNORECASE),
    },
    {
        "id": "LFI-003",
        "name": "Sensitive file access",
        "category": "lfi",
        "pattern": re.compile(r"(/etc/passwd|/etc/shadow|/proc/self|win\.ini|boot\.ini|system32)", re.IGNORECASE),
    },
    {
        "id": "LFI-004",
        "name": "Null byte injection",
        "category": "lfi",
        "pattern": re.compile(r"%00|\\x00", re.IGNORECASE),
    },

    # ═══════════════════════════════════════════════════════════
    # 5. FILE UPLOAD (DVWA File Upload) — 3 règles
    # ═══════════════════════════════════════════════════════════
    {
        "id": "FUPL-001",
        "name": "Dangerous file extension in upload",
        "category": "upload",
        "pattern": re.compile(r"filename=\"[^\"]*\.(php|php3|php4|php5|phtml|jsp|asp|aspx|exe|sh|py)\"", re.IGNORECASE),
    },
    {
        "id": "FUPL-002",
        "name": "PHP opening tag in content",
        "category": "upload",
        "pattern": re.compile(r"<\?php|<\?=|<script\s+language\s*=\s*[\"']?php[\"']?", re.IGNORECASE),
    },
    {
        "id": "FUPL-003",
        "name": "Double extension bypass",
        "category": "upload",
        "pattern": re.compile(r"\.(jpg|jpeg|png|gif|pdf)\.(php|jsp|asp)", re.IGNORECASE),
    },

    # ═══════════════════════════════════════════════════════════
    # 6. OPEN REDIRECT — 2 règles
    # ═══════════════════════════════════════════════════════════
    {
        "id": "REDIR-001",
        "name": "Open redirect parameter with external URL",
        "category": "redirect",
        "pattern": re.compile(r"(redirect|url|next|return|goto|redir)\s*=\s*(https?://|//)", re.IGNORECASE),
    },
    {
        "id": "REDIR-002",
        "name": "Redirect to IP address",
        "category": "redirect",
        "pattern": re.compile(r"(redirect|url|next|return)\s*=\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.IGNORECASE),
    },

    # ═══════════════════════════════════════════════════════════
    # 7. HEADER INJECTION — 2 règles
    # ═══════════════════════════════════════════════════════════
    {
        "id": "HDR-001",
        "name": "CRLF injection in headers",
        "category": "header_injection",
        "pattern": re.compile(r"[\r\n]\s*\w+:", re.IGNORECASE),
    },
    {
        "id": "HDR-002",
        "name": "Host header injection",
        "category": "header_injection",
        "pattern": re.compile(r"X-Forwarded-Host\s*:\s*[^\s]+", re.IGNORECASE),
    },

    # ═══════════════════════════════════════════════════════════
    # 8. BRUTE FORCE (détection pattern — complété par rate limiter)
    # ═══════════════════════════════════════════════════════════
    {
        "id": "BRUTE-001",
        "name": "Multiple login attempts pattern",
        "category": "brute_force",
        "pattern": re.compile(r"(username|user|login).{0,20}(password|pass|pwd)", re.IGNORECASE),
    },
]


def inspect(value: str) -> dict | None:
    for rule in RULES:
        if rule["pattern"].search(value):
            return rule
    return None