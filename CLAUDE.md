# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running

```bash
python recon.py
```

Requires `.env` with `ANTHROPIC_API_KEY`. Optionally set `OUTPUT_DIR` for report output path.

## Dependencies

```bash
pip install -r requirements.txt
```

Optional system package for the WHOIS fallback path (handy for .nl / .eu / exotic TLDs):

```bash
sudo apt install whois
```

## Architecture

Single-agent loop built on Anthropic tool-use API:

- `prompts.py` — system prompt defining agent persona and tool instructions
- `recon.py` — thin `ReconAIAgent` orchestrator: loads `tools.json`, runs the Anthropic agent loop, dispatches tool calls. Composes the tool mixins.
- `tools/` — one module per tool family, each exposing a `*Mixin` class:
  - `search.py` → `SearchMixin`        — web_search
  - `whois_dns.py` → `WhoisDnsMixin`   — whois_lookup, dns_lookup, subdomain_enum
  - `http.py` → `HttpMixin`            — http_fingerprint, ssl_inspect, directory_bruteforce, http_methods, vhost_discovery
  - `tcp.py` → `TcpMixin`              — port_scan, service_version_probe
  - `vuln.py` → `VulnMixin`            — cve_lookup
  - `chain.py` → `ChainMixin`          — recon_report
  - `files.py` → `FileMixin`           — write_file
  - `utils.py` → `DomainNormalizerMixin` (shared base used by several mixins)
  - `constants.py` — wordlists + TOP_100_TCP_PORTS
- `tools.json` — Anthropic tool schemas (single source of truth, loaded at import time in `recon.py`)

The mixin layout lets pytest patch `recon.httpx.get`, `recon.socket.gethostbyname`, etc. — the submodules import the same global module objects, so a single patch covers every caller.

**Agent loop** (`run_agent`): sends user query → receives `tool_use` stop → dispatches tool → appends `tool_result` → loops until `end_turn`. Report written to `OUTPUT_DIR/recon_[company]_[date]T[time]`.

## Tools

- `web_search(query)` — DuckDuckGo top-5 results via `ddgs`.
- `whois_lookup(domain)` — Primary: `python-whois`. Fallback: system `whois` CLI. Normalizes URLs (strips scheme/path) before lookup.
- `dns_lookup(domain, record_types=None)` — Active DNS enumeration via `dnspython`. Defaults to A/AAAA/MX/NS/TXT/SOA/CNAME; per-record-type errors (timeout, no answer) don't abort the whole lookup. NXDOMAIN returns early.
- `subdomain_enum(domain, limit=100)` — Passive subdomain discovery via crt.sh certificate transparency logs (no traffic to target). Deduplicates and sorts results.
- `http_fingerprint(target)` — HTTP banner grab via `httpx`: status, final URL after redirects, redirect chain, security headers, cookies, naive tech-stack hints (PHP / ASP.NET / Laravel / Rails / nginx / IIS / Cloudflare), and page title.
- `port_scan(host, ports=None, timeout=1.5, concurrency=200, banner=True)` — **ACTIVE** TCP port scan via `asyncio.open_connection`. Defaults to nmap top-100 TCP ports. Reads a tiny banner from open ports when services speak first (SSH/FTP/SMTP). Resolves hostnames before scanning so the actual scanned IP is reported. Permission required — see ethical note below.
- `directory_bruteforce(url, paths=None, concurrency=20, timeout=10)` — **ACTIVE** async HTTP path enumeration. Builtin wordlist ~60 high-value paths (dotfiles, admin panels, .git, swagger, etc.). Filters to interesting status codes (200/201/204/301/302/307/401/403/500), sorts 200s first.
- `http_methods(url)` — **ACTIVE** check of allowed HTTP methods. Reads OPTIONS Allow header AND actively probes GET/HEAD/PUT/DELETE/PATCH/TRACE. Flags PUT/DELETE/PATCH/TRACE that return <400 as RISKY.
- `vhost_discovery(target, base_domain, hostnames=None, ...)` — **ACTIVE** Host-header fuzzing. Establishes baseline with a bogus hostname, then reports vhosts whose response differs from baseline (status or content-length >50 bytes diff).
- `service_version_probe(host, ports, timeout=4, concurrency=20)` — **ACTIVE** deep service fingerprint. Per port: reads the speak-first banner, falls back to a protocol-specific probe (HTTP GET, Redis PING, memcached `version`), runs SMTP EHLO for 25/465/587. Extracts versions via regex (SSH, HTTP Server header, Redis `redis_version:`, numeric `X.Y.Z` patterns). Typically chained after `port_scan`.
- `cve_lookup(product, version="", limit=5)` — Queries NIST NVD (`services.nvd.nist.gov/rest/json/cves/2.0`). Sorts by CVSS desc, prefers v4 > v3.1 > v3 > v2 metrics. Retries with product-only if `product + version` returns empty (NVD keywordSearch is whole-word).
- `recon_report(host, skip_cve=False)` — **ACTIVE** convenience chainer. Runs `port_scan` → parses open ports → `service_version_probe` → parses `(product, version)` tuples → `cve_lookup` per service. Output is a single markdown document. Use this when you want the whole recon picture in one call. Polite 1s sleep between NVD calls.
- `write_file(file_path, content)` — Sandboxed to `OUTPUT_DIR`; refuses paths that escape the working directory.

## Known caveats

- Pyright reports false-positive attribute errors on the `python-whois` result object (dynamic dict-subclass); runtime is fine.
- Pyright may also flag `dns.resolver` as unresolved if the editor isn't pointed at the project venv — install `dnspython` in the active interpreter or configure the LSP to use `./venv`.

## Ethics

`port_scan`, `directory_bruteforce`, `http_methods`, `vhost_discovery`, and `service_version_probe` are the *active* tools in the kit — they send real packets and produce scanner-like footprints. Only run them against:
- hosts you own,
- hosts you have written permission to test,
- explicitly public scan targets such as `scanme.nmap.org` (used by the Nmap project itself for this purpose).

All other tools (`whois_lookup`, `dns_lookup`, `subdomain_enum`, `web_search`, `http_fingerprint`, `ssl_inspect`) are passive or query-only and produce no scanner-like footprint on the target. `http_fingerprint` and `ssl_inspect` do open a single normal connection each — fine in almost every context but still log-visible.
