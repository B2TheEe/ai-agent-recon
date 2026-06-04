# ai-agent-recon

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
| `port_scan`         | **ACTIVE** | Async TCP connect-scan + banner grab, nmap top-100 by default                   |
| `write_file`        | local   | Sandboxed writes to `OUTPUT_DIR`                                                   |

`port_scan` is the only tool that touches the target with scanner-like traffic. Only run it against hosts you own or have written permission to test (`scanme.nmap.org` is a safe public target).

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

A weekly GitHub Actions workflow (`smoke.yml`) runs `smoke_test.py` every Monday and uploads the report as an artifact. Manual runs available via the Actions tab.

## Project layout

```
recon.py            ReconAIAgent + agent loop + tool implementations
tools.json          Anthropic tool schemas (single source of truth)
prompts.py          system prompt
smoke_test.py       end-to-end tool integration check
requirements.txt    pinned deps
.github/workflows/  CI
```

## Disclaimer

For authorized security testing only. Active tools (`port_scan`) send real packets — make sure you have explicit permission for any target you scan.
