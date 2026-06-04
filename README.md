# ai-agent-recon

[![tests](https://github.com/B2TheEe/ai-agent-recon/actions/workflows/tests.yml/badge.svg)](https://github.com/B2TheEe/ai-agent-recon/actions/workflows/tests.yml)
[![smoke](https://github.com/B2TheEe/ai-agent-recon/actions/workflows/smoke.yml/badge.svg)](https://github.com/B2TheEe/ai-agent-recon/actions/workflows/smoke.yml)

AI-powered reconnaissance agent. Give it a target company and Claude orchestrates a toolkit of passive + active recon utilities to produce a structured report.

## Tools available to the agent

| Tool                | Type    | What it does                                                                       |
|---------------------|---------|------------------------------------------------------------------------------------|
| `web_search`        | passive | DuckDuckGo top-5 results via `ddgs`                                                |
| `whois_lookup`      | passive | Registrar, dates, nameservers, registrant — `python-whois` + system `whois` fallback |
| `dns_lookup`        | passive | A/AAAA/MX/NS/TXT/SOA/CNAME (configurable) via `dnspython`                          |
| `subdomain_enum`    | passive | Certificate transparency search via crt.sh                                         |
| `http_fingerprint`  | passive | Status, security headers, redirect chain, cookies, tech-stack hints, page title    |
| `ssl_inspect`       | passive | TLS cert subject/issuer/SANs/validity, negotiated version + cipher                 |
| `port_scan`            | **ACTIVE** | Async TCP connect-scan + banner grab, nmap top-100 by default                |
| `directory_bruteforce` | **ACTIVE** | Async HTTP path enum — dotfiles, admin, .git, swagger, etc. (~60 paths)      |
| `http_methods`         | **ACTIVE** | Probes GET/HEAD/OPTIONS/PUT/DELETE/PATCH/TRACE; flags risky methods          |
| `vhost_discovery`      | **ACTIVE** | Host-header fuzzing to find vhosts not in DNS; baseline-anomaly detection    |
| `service_version_probe` | **ACTIVE** | Deep per-port fingerprint: SSH/SMTP/HTTP/Redis/memcached + version extract  |
| `cve_lookup`           | passive    | NVD CVE search by product + version, sorted by CVSS                          |
| `recon_report`         | **ACTIVE** | End-to-end chainer: port_scan → service_version_probe → cve_lookup → markdown |
| `write_file`           | local      | Sandboxed writes to `OUTPUT_DIR`                                             |

`port_scan`, `directory_bruteforce`, `http_methods`, `vhost_discovery`, and `service_version_probe` are **ACTIVE** — they send real packets and appear in target logs. Only run them against hosts you own or have written permission to test. `scanme.nmap.org` (port_scan) and `httpbin.org` (HTTP tools, owned by Postman, allows automated traffic) are safe public targets for verifying the toolkit works.

## Setup

```bash
git clone https://github.com/B2TheEe/ai-agent-recon
cd ai-agent-recon
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
sudo apt install whois          # optional, enables fallback for exotic TLDs
```

Create `.env`:

```
ANTHROPIC_API_KEY=your_key_here
OUTPUT_DIR=output                # optional, defaults to ./output
```

## Usage

Run the agent (prompts for a target):

```bash
python recon.py
```

Run the tool-layer smoke test (no LLM, no API key needed):

```bash
python smoke_test.py
# or with custom targets you control:
SMOKE_DOMAIN=yourdomain.com SMOKE_SCAN_HOST=yourhost.com python smoke_test.py
```

## CI

Two GitHub Actions workflows:

- **`tests.yml`** — fast offline pytest suite, runs on every push and PR (~1 sec)
- **`smoke.yml`** — weekly live integration test against real endpoints, uploads report as artifact

## Running tests locally

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

## Project layout

```
recon.py            ReconAIAgent thin orchestrator + agent loop
tools/              tool implementations split per family (mixin pattern)
  ├ search.py        web_search
  ├ whois_dns.py     whois_lookup, dns_lookup, subdomain_enum
  ├ http.py          http_fingerprint, ssl_inspect, directory_bruteforce, http_methods, vhost_discovery
  ├ tcp.py           port_scan, service_version_probe
  ├ vuln.py          cve_lookup
  ├ chain.py         recon_report
  ├ files.py         write_file (sandboxed)
  ├ utils.py         DomainNormalizerMixin (shared)
  └ constants.py     wordlists, port lists
tools.json          Anthropic tool schemas (single source of truth)
prompts.py          system prompt
smoke_test.py       end-to-end tool integration check
tests/              pytest unit tests (mocked, offline)
examples/           sample recon report output
requirements.txt    pinned deps
requirements-dev.txt  dev deps (pytest)
.github/workflows/  CI (tests.yml + smoke.yml)
```

## Disclaimer

For authorized security testing only. Active tools (`port_scan`) send real packets — make sure you have explicit permission for any target you scan.
