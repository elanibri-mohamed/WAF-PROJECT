#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  Phase 4 — Automated Attack Script
#
#  Fires a comprehensive set of SQLi and XSS payloads at:
#    Target A — Unprotected DVWA        :8888
#    Target B — ModSecurity WAF         :8080
#    Target C — Custom Python WAF       :8090
#
#  Collects: status codes, block rates, bypasses, false positives
#  Outputs:  console table + results-summary.md
#
#  Requirements: pip install requests rich
#  Usage:        python attack_script.py
#                python attack_script.py --session <PHPSESSID>
# ─────────────────────────────────────────────────────────────

import argparse
import time
import json
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional
import requests
from requests.exceptions import ConnectionError, Timeout

# ── Targets ───────────────────────────────────────────────────
TARGETS = {
    "Unprotected (8888)":   "http://localhost:8888",
    "ModSecurity (8080)":   "http://localhost:8080",
    "Custom WAF (8090)":    "http://localhost:8090",
}

REQUEST_TIMEOUT = 8  # seconds

# ── Payloads ──────────────────────────────────────────────────
# Each payload: (label, category, endpoint, method, param, value)

ATTACK_PAYLOADS = [
    # ── SQLi — GET parameter ──────────────────────────────────
    ("UNION SELECT dump",       "SQLi", "/vulnerabilities/sqli/",     "GET",  "id", "1' UNION SELECT user,password FROM users-- -"),
    ("Tautology OR 1=1",        "SQLi", "/vulnerabilities/sqli/",     "GET",  "id", "1' OR '1'='1"),
    ("Tautology OR 1=1 #2",     "SQLi", "/vulnerabilities/sqli/",     "GET",  "id", "' OR 1=1--"),
    ("Quote error probe",       "SQLi", "/vulnerabilities/sqli/",     "GET",  "id", "1'"),
    ("Blind SLEEP",             "SQLi", "/vulnerabilities/sqli/",     "GET",  "id", "1' AND SLEEP(1)-- -"),
    ("Comment sequence --",     "SQLi", "/vulnerabilities/sqli/",     "GET",  "id", "1'-- -"),
    ("Stacked query attempt",   "SQLi", "/vulnerabilities/sqli/",     "GET",  "id", "1'; DROP TABLE users--"),
    ("UNION 2-col",             "SQLi", "/vulnerabilities/sqli/",     "GET",  "id", "0 UNION SELECT 1,2"),
    ("Encoded UNION",           "SQLi", "/vulnerabilities/sqli/",     "GET",  "id", "1%27%20UNION%20SELECT%201%2C2--"),
    ("Boolean AND 1=2",         "SQLi", "/vulnerabilities/sqli/",     "GET",  "id", "1' AND 1=2--"),

    # ── SQLi — Blind (POST) ───────────────────────────────────
    ("POST SQLi username",      "SQLi", "/login.php",                 "POST", "username", "admin'--"),
    ("POST SQLi password",      "SQLi", "/login.php",                 "POST", "password", "' OR '1'='1"),

    # ── XSS — Reflected ───────────────────────────────────────
    ("Script tag alert",        "XSS",  "/vulnerabilities/xss_r/",    "GET",  "name", "<script>alert(1)</script>"),
    ("IMG onerror",             "XSS",  "/vulnerabilities/xss_r/",    "GET",  "name", "<img src=x onerror=alert(1)>"),
    ("SVG onload",              "XSS",  "/vulnerabilities/xss_r/",    "GET",  "name", "<svg onload=alert(1)>"),
    ("javascript: URI",         "XSS",  "/vulnerabilities/xss_r/",    "GET",  "name", "<a href=javascript:alert(1)>x</a>"),
    ("Event attr onfocus",      "XSS",  "/vulnerabilities/xss_r/",    "GET",  "name", "<input onfocus=alert(1) autofocus>"),
    ("Encoded script",          "XSS",  "/vulnerabilities/xss_r/",    "GET",  "name", "%3Cscript%3Ealert(1)%3C/script%3E"),
    ("document.cookie",         "XSS",  "/vulnerabilities/xss_r/",    "GET",  "name", "<script>document.cookie</script>"),
    ("iframe injection",        "XSS",  "/vulnerabilities/xss_r/",    "GET",  "name", "<iframe src=javascript:alert(1)>"),

    # ── XSS — Stored (POST) ───────────────────────────────────
    ("Stored XSS message",      "XSS",  "/vulnerabilities/xss_s/",    "POST", "mtxMessage", "<script>alert('stored')</script>"),
    ("Stored SVG payload",      "XSS",  "/vulnerabilities/xss_s/",    "POST", "mtxMessage", "<svg onload=alert(1)>"),

    # ── Bypass attempts ───────────────────────────────────────
    ("XSS case variation",      "XSS",  "/vulnerabilities/xss_r/",    "GET",  "name", "<ScRiPt>alert(1)</sCrIpT>"),
    ("XSS double encode",       "XSS",  "/vulnerabilities/xss_r/",    "GET",  "name", "%253Cscript%253Ealert(1)%253C%252Fscript%253E"),
    ("SQLi space bypass",       "SQLi", "/vulnerabilities/sqli/",     "GET",  "id",   "1'/**/OR/**/1=1--"),
    ("SQLi comment bypass",     "SQLi", "/vulnerabilities/sqli/",     "GET",  "id",   "1'/*!OR*/1=1--"),
]

# ── Legitimate requests (false positive check) ────────────────
LEGIT_REQUESTS = [
    ("Home page",        "GET",  "/",               None,       None),
    ("Login page load",  "GET",  "/login.php",      None,       None),
    ("Setup page",       "GET",  "/setup.php",      None,       None),
    ("SQLi page load",   "GET",  "/vulnerabilities/sqli/",   None, None),
    ("XSS page load",    "GET",  "/vulnerabilities/xss_r/",  None, None),
    ("Normal search",    "GET",  "/vulnerabilities/sqli/",   "id", "1"),
    ("Normal name",      "GET",  "/vulnerabilities/xss_r/",  "name", "Alice"),
]


@dataclass
class Result:
    label: str
    category: str
    endpoint: str
    method: str
    param: str
    payload: str
    status: int
    blocked: bool
    duration_ms: float
    error: Optional[str] = None


@dataclass
class TargetReport:
    name: str
    base_url: str
    attack_results: list[Result] = field(default_factory=list)
    legit_results: list[Result] = field(default_factory=list)

    @property
    def total_attacks(self): return len(self.attack_results)

    @property
    def blocked(self): return sum(1 for r in self.attack_results if r.blocked)

    @property
    def bypassed(self): return sum(1 for r in self.attack_results if not r.blocked and not r.error)

    @property
    def errors(self): return sum(1 for r in self.attack_results if r.error)

    @property
    def block_rate(self):
        denom = self.total_attacks - self.errors
        return (self.blocked / denom * 100) if denom > 0 else 0

    @property
    def false_positives(self): return sum(1 for r in self.legit_results if r.blocked)

    @property
    def avg_latency(self):
        times = [r.duration_ms for r in self.attack_results if not r.error]
        return sum(times) / len(times) if times else 0


def make_request(base_url: str, method: str, endpoint: str,
                 param: str, value: str, session_cookie: str) -> tuple[int, bool, float, Optional[str]]:
    """Fire a single request. Returns (status, blocked, duration_ms, error)."""
    url = base_url + endpoint
    cookies = {"PHPSESSID": session_cookie, "security": "low"} if session_cookie else {"security": "low"}
    headers = {"User-Agent": "WAF-Tester/1.0"}

    t0 = time.monotonic()
    try:
        if method == "GET":
            params = {param: value} if param else {}
            resp = requests.get(url, params=params, cookies=cookies,
                                headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        else:  # POST
            data = {param: value, "Submit": "Submit"} if param else {}
            resp = requests.post(url, data=data, cookies=cookies,
                                 headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)

        duration_ms = (time.monotonic() - t0) * 1000
        blocked = resp.status_code == 403
        return resp.status_code, blocked, duration_ms, None

    except ConnectionError:
        return 0, False, 0, "CONNECTION_ERROR"
    except Timeout:
        return 0, False, 0, "TIMEOUT"
    except Exception as e:
        return 0, False, 0, str(e)


def run_attacks(target_name: str, base_url: str, session_cookie: str) -> TargetReport:
    report = TargetReport(name=target_name, base_url=base_url)

    print(f"\n{'─'*60}")
    print(f"  Target: {target_name}  ({base_url})")
    print(f"{'─'*60}")

    # ── Attack payloads ───────────────────────────────────────
    print(f"  Firing {len(ATTACK_PAYLOADS)} attack payloads...")
    for label, category, endpoint, method, param, payload in ATTACK_PAYLOADS:
        status, blocked, dur, err = make_request(
            base_url, method, endpoint, param, payload, session_cookie
        )
        icon = "🔴 BLOCKED" if blocked else ("⚪ ERROR" if err else "🟢 PASSED")
        print(f"    [{icon}] {label:<30} → {status}  ({dur:.0f}ms)")

        report.attack_results.append(Result(
            label=label, category=category, endpoint=endpoint,
            method=method, param=param, payload=payload,
            status=status, blocked=blocked, duration_ms=dur, error=err
        ))
        time.sleep(0.1)  # polite delay

    # ── Legit requests (false positive check) ─────────────────
    print(f"\n  Checking {len(LEGIT_REQUESTS)} legitimate requests (false positive test)...")
    for label, method, endpoint, param, value in LEGIT_REQUESTS:
        status, blocked, dur, err = make_request(
            base_url, method, endpoint, param or "", value or "", session_cookie
        )
        icon = "⚠️  FALSE+" if blocked else "✅ OK"
        print(f"    [{icon}] {label:<30} → {status}  ({dur:.0f}ms)")

        report.legit_results.append(Result(
            label=label, category="legit", endpoint=endpoint,
            method=method, param=param or "", payload=value or "",
            status=status, blocked=blocked, duration_ms=dur, error=err
        ))
        time.sleep(0.1)

    return report


def print_summary(reports: list[TargetReport]) -> None:
    print(f"\n\n{'═'*70}")
    print("  RESULTS SUMMARY")
    print(f"{'═'*70}")
    header = f"  {'Target':<28} {'Blocked':>8} {'Bypassed':>9} {'Block%':>7} {'FP':>5} {'Latency':>10}"
    print(header)
    print(f"  {'─'*65}")
    for r in reports:
        print(
            f"  {r.name:<28} {r.blocked:>8}/{r.total_attacks:<3}"
            f" {r.bypassed:>7}   {r.block_rate:>6.1f}%"
            f" {r.false_positives:>4}   {r.avg_latency:>7.0f}ms"
        )
    print(f"{'═'*70}")


def write_markdown(reports: list[TargetReport]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Phase 4 — Testing Results\n",
        f"**Generated:** {now}  \n",
        f"**Total payloads fired:** {len(ATTACK_PAYLOADS)} attacks + {len(LEGIT_REQUESTS)} legit requests per target\n\n",
        "---\n\n",
        "## Summary Table\n\n",
        "| Target | Blocked | Bypassed | Block Rate | False Positives | Avg Latency |\n",
        "|--------|---------|----------|------------|-----------------|-------------|\n",
    ]
    for r in reports:
        lines.append(
            f"| {r.name} | {r.blocked}/{r.total_attacks} | {r.bypassed} "
            f"| **{r.block_rate:.1f}%** | {r.false_positives} | {r.avg_latency:.0f}ms |\n"
        )

    lines += ["\n---\n\n## Per-Target Detail\n"]

    for r in reports:
        lines += [
            f"\n### {r.name}\n\n",
            f"- **Block rate:** {r.block_rate:.1f}%  \n",
            f"- **Blocked:** {r.blocked} / {r.total_attacks}  \n",
            f"- **Bypassed:** {r.bypassed}  \n",
            f"- **False positives:** {r.false_positives}  \n",
            f"- **Avg response time:** {r.avg_latency:.0f}ms  \n\n",
            "#### Attack Results\n\n",
            "| # | Label | Category | Status | Blocked |\n",
            "|---|-------|----------|--------|---------|\n",
        ]
        for i, res in enumerate(r.attack_results, 1):
            blocked_str = "🔴 YES" if res.blocked else ("⚪ ERR" if res.error else "🟢 NO")
            lines.append(f"| {i} | {res.label} | {res.category} | {res.status} | {blocked_str} |\n")

        # Bypassed payloads
        bypassed = [res for res in r.attack_results if not res.blocked and not res.error]
        if bypassed:
            lines += ["\n#### ⚠️ Bypassed Payloads\n\n"]
            for res in bypassed:
                lines.append(f"- `{res.payload}` — *{res.label}* ({res.category})\n")

        # False positives
        fps = [res for res in r.legit_results if res.blocked]
        if fps:
            lines += ["\n#### ⚠️ False Positives\n\n"]
            for res in fps:
                lines.append(f"- `{res.label}` — blocked with status {res.status}\n")
        else:
            lines.append("\n✅ No false positives detected.\n")

    lines += [
        "\n---\n\n## Analysis Notes\n\n",
        "*(Fill in after reviewing results)*\n\n",
        "- **Unprotected:** All attacks pass through — baseline confirms DVWA is genuinely vulnerable.\n",
        "- **ModSecurity CRS:** Industry-standard rule set. Note any bypasses and which CRS rules fired.\n",
        "- **Custom WAF:** Regex-based detection. Compare bypass patterns vs ModSecurity — useful for the report's comparison section.\n",
        "\n---\n\n## Nikto Scan Commands\n\n",
        "Run these after the automated script to add depth to Phase 4:\n\n",
        "```bash\n",
        "# Unprotected\n",
        "nikto -h http://localhost:8888 -output zap-reports/nikto-unprotected.txt\n\n",
        "# ModSecurity WAF\n",
        "nikto -h http://localhost:8080 -output zap-reports/nikto-modsecurity.txt\n\n",
        "# Custom WAF\n",
        "nikto -h http://localhost:8090 -output zap-reports/nikto-custom-waf.txt\n",
        "```\n\n",
        "Compare the number of vulnerabilities found across all three — fewer findings behind the WAFs = better protection.\n",
    ]

    with open("results-summary.md", "w", encoding="utf-8") as f:
        f.writelines(lines)

    print(f"\n  📄 Report written to: results-summary.md")


def main():
    parser = argparse.ArgumentParser(description="WAF Attack Tester — Phase 4")
    parser.add_argument(
        "--session", "-s",
        help="PHPSESSID cookie from a logged-in DVWA session",
        default=""
    )
    args = parser.parse_args()

    if not args.session:
        print("\n⚠️  No --session provided. Some DVWA endpoints need authentication.")
        print("   Log into DVWA, grab your PHPSESSID from DevTools → Application → Cookies")
        print("   Then run: python attack_script.py --session <your_phpsessid>\n")

    print("\n" + "═"*60)
    print("  WAF Showdown — Phase 4 Attack Script")
    print("  Targets: Unprotected | ModSecurity | Custom WAF")
    print("═"*60)

    reports = []
    for name, base_url in TARGETS.items():
        report = run_attacks(name, base_url, args.session)
        reports.append(report)

    print_summary(reports)
    write_markdown(reports)


if __name__ == "__main__":
    main()