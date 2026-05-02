# Phase 4 — Testing Results
**Generated:** 2026-05-02 11:01 UTC  
**Total payloads fired:** 26 attacks + 7 legit requests per target

---

## Summary Table

| Target | Blocked | Bypassed | Block Rate | False Positives | Avg Latency |
|--------|---------|----------|------------|-----------------|-------------|
| Unprotected (8888) | 0/26 | 26 | **0.0%** | 0 | 57ms |
| ModSecurity (8080) | 23/26 | 3 | **88.5%** | 0 | 66ms |
| Custom WAF (8090) | 25/26 | 1 | **96.2%** | 0 | 75ms |

---

## Per-Target Detail

### Unprotected (8888)

- **Block rate:** 0.0%  
- **Blocked:** 0 / 26  
- **Bypassed:** 26  
- **False positives:** 0  
- **Avg response time:** 57ms  

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
| 23 | XSS case variation | XSS | 200 | 🟢 NO |
| 24 | XSS double encode | XSS | 200 | 🟢 NO |
| 25 | SQLi space bypass | SQLi | 200 | 🟢 NO |
| 26 | SQLi comment bypass | SQLi | 200 | 🟢 NO |

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

✅ No false positives detected.

### ModSecurity (8080)

- **Block rate:** 88.5%  
- **Blocked:** 23 / 26  
- **Bypassed:** 3  
- **False positives:** 0  
- **Avg response time:** 66ms  

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
| 23 | XSS case variation | XSS | 403 | 🔴 YES |
| 24 | XSS double encode | XSS | 200 | 🟢 NO |
| 25 | SQLi space bypass | SQLi | 403 | 🔴 YES |
| 26 | SQLi comment bypass | SQLi | 403 | 🔴 YES |

#### ⚠️ Bypassed Payloads

- `1'` — *Quote error probe* (SQLi)
- `1'-- -` — *Comment sequence --* (SQLi)
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

✅ No false positives detected.

### Custom WAF (8090)

- **Block rate:** 96.2%  
- **Blocked:** 25 / 26  
- **Bypassed:** 1  
- **False positives:** 0  
- **Avg response time:** 75ms  

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
| 23 | XSS case variation | XSS | 403 | 🔴 YES |
| 24 | XSS double encode | XSS | 403 | 🔴 YES |
| 25 | SQLi space bypass | SQLi | 403 | 🔴 YES |
| 26 | SQLi comment bypass | SQLi | 403 | 🔴 YES |

#### ⚠️ Bypassed Payloads

- `1'` — *Quote error probe* (SQLi)

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
