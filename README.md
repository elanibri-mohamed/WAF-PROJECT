# Under the Hood — WAF Project

> Deploying and analysing ModSecurity as a reverse-proxy WAF in front of DVWA.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Docker Network                     │
│                                                      │
│  Browser ──► :8080 ──► [ModSecurity/Nginx WAF]      │
│                               │  (Phase 2)           │
│                               ▼                      │
│                          [DVWA :80]  ◄── [MariaDB]  │
│                                                      │
│  Browser ──► :8888 ──► [DVWA :80]  (Phase 1, raw)  │
└─────────────────────────────────────────────────────┘
```

| Port   | What                          | When to use        |
|--------|-------------------------------|--------------------|
| `8888` | DVWA unprotected (raw)        | Phase 1 exploiting |
| `8080` | DVWA behind ModSecurity WAF   | Phase 2 testing    |

---

## Prerequisites

- Docker Engine ≥ 24
- Docker Compose v2
- ~1 GB free disk space

---

## Quick Start

### Phase 1 — Unprotected target only

```bash
# Start DVWA + DB (no WAF)
docker compose up dvwa db -d

# Browse to:
open http://localhost:8888/setup.php
# Click "Create / Reset Database"
# Login: admin / password
# Set security level to: Low
```

See [`phase1-target/exploit-notes.md`](phase1-target/exploit-notes.md) for the full attack walkthrough.

### Phase 2 — Full stack with ModSecurity WAF

```bash
# Bring up everything
docker compose up -d

# WAF-protected endpoint:
open http://localhost:8080

# Unprotected still available for comparison:
open http://localhost:8888
```

---

## Verifying the WAF Blocks Attacks

Run these from your terminal. The WAF endpoint should return `403 Forbidden`.

```bash
# SQLi — Union-based
curl -i "http://localhost:8080/vulnerabilities/sqli/?id=1'+UNION+SELECT+1,2--+-&Submit=Submit" \
     -b "PHPSESSID=<your_session>; security=low"

# SQLi — Tautology
curl -i "http://localhost:8080/vulnerabilities/sqli/?id=1'+OR+'1'%3D'1&Submit=Submit" \
     -b "PHPSESSID=<your_session>; security=low"

# XSS — Reflected
curl -i "http://localhost:8080/vulnerabilities/xss_r/?name=<script>alert(1)</script>&Submit=Submit" \
     -b "PHPSESSID=<your_session>; security=low"
```

Expected response:
```
HTTP/1.1 403 Forbidden
X-WAF-Protected: ModSecurity/CRS
```

Same payloads against `localhost:8888` (unprotected) should succeed.

---

## WAF Configuration Files

| File | Purpose |
|------|---------|
| `phase2-modsecurity/nginx/default.conf` | Nginx reverse proxy — forwarding rules, headers, 403 page |
| `phase2-modsecurity/crs-setup/custom-exclusions.conf` | Per-URI exclusions to eliminate DVWA false positives |
| `docker-compose.yml` | Environment variables controlling CRS paranoia level and mode |

### Key tuning knobs (in `docker-compose.yml`)

```yaml
MODSEC_RULE_ENGINE: "On"      # On | DetectionOnly | Off
PARANOIA: 1                    # 1 (low FP) → 4 (max detection)
ANOMALY_INBOUND: 5             # Score threshold to block a request
ANOMALY_OUTBOUND: 4            # Score threshold to block a response
```

Raise `PARANOIA` to `2` when you want stricter detection at the cost of more false positives.

---

## Viewing WAF Logs

```bash
# Live log stream from the WAF container
docker compose logs -f waf

# Access the raw log files
docker exec modsec-waf tail -f /var/log/nginx/error.log

# Filter only ModSecurity block events
docker exec modsec-waf grep -i "ModSecurity" /var/log/nginx/error.log | grep "Access denied"
```

A blocked request looks like:

```
[error] ModSecurity: Access denied with code 403 (phase 2).
  Matched Data: "UNION SELECT" found within ARGS:id
  [id "942100"] [msg "SQL Injection Attack Detected via libinjection"]
  [tag "attack-sqli"]
  [hostname "localhost"] [uri "/vulnerabilities/sqli/"]
  [unique_id "..."]
```

---

## Stopping Everything

```bash
docker compose down          # stop containers, keep volumes
docker compose down -v       # stop containers AND delete DB data
```

---

## Project Structure

```
waf-project/
├── docker-compose.yml                        ← orchestrates all services
├── README.md
│
├── phase1-target/
│   ├── exploit-notes.md                      ← manual attack walkthrough
│   └── screenshots/                          ← proof of vulnerability
│
└── phase2-modsecurity/
    ├── nginx/
    │   └── default.conf                      ← reverse proxy config
    ├── crs-setup/
    │   └── custom-exclusions.conf            ← DVWA false-positive tuning
    └── screenshots/                          ← proof of WAF blocking
```