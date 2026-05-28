# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running

```bash
python recon.py
```

Requires `.env` with `ANTHROPIC_API_KEY`. Optionally set `OUTPUT_DIR` for report output path.

## Dependencies

```bash
pip install anthropic duckduckgo-search python-dotenv
```

## Architecture

Single-agent loop built on Anthropic tool-use API:

- `prompts.py` — system prompt defining agent persona and tool instructions
- `recon.py` — `ReconAIAgent` class with agent loop, tools (`web_search`, `write_file`), entry point
- `tools.json` — Anthropic tool schemas (passed as `tools=` in API call)

**Agent loop** (`run_agent`): sends user query → receives `tool_use` stop → dispatches tool → appends `tool_result` → loops until `end_turn`. Report written to `OUTPUT_DIR/recon_[company]_[date]T[time]`.

## Known Issues

- `tools=` is commented out in `client.messages.create` — agent never triggers tool use
- `web_search` missing `self` param and returns `None` (no `return` statement)
- Message role set to `"senior ethical hacker"` instead of `"assistant"` — API will reject
- `execute_tool` called but never defined
- `return "Max iterations reached..."` inside the tool loop, exits after first tool call
