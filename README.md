# ai-agent-recon

AI-powered passive reconnaissance agent. Given a target company, uses Claude to orchestrate web searches and produce a structured recon report.

## What it does

- Web searches for infrastructure, DNS records, subdomains, and tech stack
- Writes a timestamped report to the output directory (`recon_[company]_[date]T[time]`)
- Prints next recommended pentest steps to terminal

## Setup

```bash
pip install anthropic duckduckgo-search python-dotenv
```

Create `.env`:

```
ANTHROPIC_API_KEY=your_key_here
OUTPUT_DIR=output        # optional, defaults to ./output
```

## Usage

```bash
python recon.py
```

Prompts for a target company name, then runs the agent loop autonomously.

## Disclaimer

For authorized security testing only. Only run against targets you have explicit permission to test.
