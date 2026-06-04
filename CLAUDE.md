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
- `recon.py` — `ReconAIAgent` class with agent loop, tools (`web_search`, `whois_lookup`, `write_file`), entry point
- `tools.json` — Anthropic tool schemas (reference copy; the live schemas are defined inline in `recon.py`)

**Agent loop** (`run_agent`): sends user query → receives `tool_use` stop → dispatches tool → appends `tool_result` → loops until `end_turn`. Report written to `OUTPUT_DIR/recon_[company]_[date]T[time]`.

## Tools

- `web_search(query)` — DuckDuckGo top-5 results via `ddgs`.
- `whois_lookup(domain)` — Primary: `python-whois`. Fallback: system `whois` CLI. Normalizes URLs (strips scheme/path) before lookup.
- `write_file(file_path, content)` — Sandboxed to `OUTPUT_DIR`; refuses paths that escape the working directory.

## Known caveats

- `tools.json` is a reference copy only — schemas are defined inline in `recon.py`. Keep both in sync until/unless the inline list is replaced by a JSON load.
- Pyright reports false-positive attribute errors on the `python-whois` result object (dynamic dict-subclass); runtime is fine.
