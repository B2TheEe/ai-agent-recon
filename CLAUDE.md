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
- `recon.py` — `ReconAIAgent` class with agent loop, tools (`web_search`, `whois_lookup`, `dns_lookup`, `write_file`), entry point
- `tools.json` — Anthropic tool schemas (single source of truth, loaded at import time in `recon.py`)

**Agent loop** (`run_agent`): sends user query → receives `tool_use` stop → dispatches tool → appends `tool_result` → loops until `end_turn`. Report written to `OUTPUT_DIR/recon_[company]_[date]T[time]`.

## Tools

- `web_search(query)` — DuckDuckGo top-5 results via `ddgs`.
- `whois_lookup(domain)` — Primary: `python-whois`. Fallback: system `whois` CLI. Normalizes URLs (strips scheme/path) before lookup.
- `dns_lookup(domain, record_types=None)` — Active DNS enumeration via `dnspython`. Defaults to A/AAAA/MX/NS/TXT/SOA/CNAME; per-record-type errors (timeout, no answer) don't abort the whole lookup. NXDOMAIN returns early.
- `write_file(file_path, content)` — Sandboxed to `OUTPUT_DIR`; refuses paths that escape the working directory.

## Known caveats

- Pyright reports false-positive attribute errors on the `python-whois` result object (dynamic dict-subclass); runtime is fine.
- Pyright may also flag `dns.resolver` as unresolved if the editor isn't pointed at the project venv — install `dnspython` in the active interpreter or configure the LSP to use `./venv`.
