# Under the Hood — WAF Project

> Deploying and analysing ModSecurity and a custom Python WAF in front of DVWA.

---

## Current Progress

- Phase 1 complete: unprotected DVWA is running on `http://localhost:8888` and serves as the baseline vulnerable target.
- Phase 2 complete: ModSecurity is deployed on `http://localhost:8080` and blocks most SQLi/XSS payloads.
- Phase 3 complete: custom Python WAF is running on `http://localhost:8090` and currently blocks 25/26 attack payloads in automated tests.
- Phase 4 in progress: `phase4-testing/attack_script.py` automates 26 attack payloads and 7 legitimate requests per target, generating `phase4-testing/results-summary.md`.

## Getting Started

```bash
# Clone the repository
git clone https://github.com/elanibri-mohamed/WAF-PROJECT waf-project
cd waf-project

# Build and run the Docker infrastructure
docker compose up -d

# Confirm services are running
docker compose ps
```

### Quick validation

```bash
# Test the unprotected DVWA target
curl -I http://localhost:8888

# Test the ModSecurity protected endpoint
curl -I http://localhost:8080

# Test the custom WAF endpoint
curl -I http://localhost:8090
```

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
│                                                      │
│  Browser ──► :8090 ──► [Custom Python WAF]          │
└─────────────────────────────────────────────────────┘
```

| Port   | What                                  | When to use        |
|--------|---------------------------------------|--------------------|
| `8888` | DVWA unprotected (raw)                | Phase 1 exploiting |
| `8080` | DVWA behind ModSecurity WAF           | Phase 2 testing    |
| `8090` | DVWA behind custom Python/aiohttp WAF | Phase 3 testing    |

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
http://localhost:8888/setup.php
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
http://localhost:8080

# Unprotected still available for comparison:
http://localhost:8888
```

### Phase 3 — Custom Python WAF

```bash
# Build and run the custom WAF service
docker compose up -d phase3-waf

# Custom WAF endpoint:
http://localhost:8090
```

### Phase 4 — Automated testing

```bash
cd phase4-testing
python attack_script.py --session <your_phpsessid>
```

- Generates `results-summary.md` with attack results for all three targets.
- Verifies the custom WAF, ModSecurity WAF, and unprotected DVWA using 26 attack payloads plus 7 legit requests.
- Current observed block rates: `ModSecurity ~88.5%`, `Custom WAF ~96.2%`, with no false positives in the latest run.

---

## Verifying the WAF Blocks Attacks

Run these from your terminal. The WAF endpoint should return `403 Forbidden`.

```bash
# SQLi — Union-based through ModSecurity
curl -i "http://localhost:8080/vulnerabilities/sqli/?id=1'+UNION+SELECT+1,2--+-&Submit=Submit" \
     -b "PHPSESSID=<your_session>; security=low"

# XSS — Reflected through ModSecurity
curl -i "http://localhost:8080/vulnerabilities/xss_r/?name=<script>alert(1)</script>&Submit=Submit" \
     -b "PHPSESSID=<your_session>; security=low"

# SQLi — Union-based through custom WAF
curl -i "http://localhost:8090/vulnerabilities/sqli/?id=1'+UNION+SELECT+1,2--+-&Submit=Submit" \
     -b "PHPSESSID=<your_session>; security=low"

# XSS — Reflected through custom WAF
curl -i "http://localhost:8090/vulnerabilities/xss_r/?name=<script>alert(1)</script>&Submit=Submit" \
     -b "PHPSESSID=<your_session>; security=low"
```

Expected response from either WAF:
```
HTTP/1.1 403 Forbidden
```

Same payloads against `localhost:8888` (unprotected) should succeed.

---

## WAF Configuration Files

| File | Purpose |
|------|---------|
| `phase2-modsecurity/nginx/default.conf` | Nginx reverse proxy config for ModSecurity |
| `phase2-modsecurity/crs-setup/custom-exclusions.conf` | Custom exclusions to reduce DVWA false positives |
| `phase3-custom-waf/Dockerfile` | Container build for the custom aiohttp WAF |
| `phase3-custom-waf/config.py` | Runtime settings and Docker environment integration |
| `docker-compose.yml` | Orchestrates DVWA, DB, ModSecurity WAF, and custom WAF |

### Key tuning knobs (in `docker-compose.yml`)

```yaml
MODSEC_RULE_ENGINE: "On"      # On | DetectionOnly | Off
PARANOIA: 1                    # 1 (low FP) → 4 (max detection)
ANOMALY_INBOUND: 5             # Score threshold to block a request
ANOMALY_OUTBOUND: 4            # Score threshold to block a response
```

---

## Viewing WAF Logs

### Phase 2 (ModSecurity)

```bash
docker compose logs -f waf
```

### Phase 3 (Custom WAF)

```bash
docker compose logs -f phase3-waf
```

### Inspect custom WAF log file

```bash
# On the host
cat phase3-custom-waf/logs/waf-blocks.log
```

A blocked request from the custom WAF looks like a pipe-delimited log entry:

```
TIMESTAMP | ATTACKER_IP | RULE_ID | RULE_NAME | LOCATION | PAYLOAD
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
├── report/
│   └── final-report.md                      ← consolidated progress report
├── phase1-target/
│   ├── exploit-notes.md                      ← manual attack walkthrough
│   └── screenshots/                          ← proof of vulnerability
├── phase2-modsecurity/
│   ├── nginx/
│   │   └── default.conf                      ← reverse proxy config
│   ├── crs-setup/
│   │   └── custom-exclusions.conf            ← DVWA false-positive tuning
│   └── screenshots/                          ← proof of WAF blocking
└── phase3-custom-waf/
    ├── waf.py                               ← custom Python WAF entrypoint
    ├── config.py                            ← runtime settings and Docker integration
    ├── engine/                              ← detection logic and response components
    ├── logs/                                ← WAF block logs
    ├── screenshots/                          ← Phase 3 proof of blocks and logs
    └── Dockerfile                           ← custom WAF container build
```
