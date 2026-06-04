"""
End-to-end smoke test for the recon agent toolkit.

Runs every tool sequentially against a permitted target and writes a single
consolidated markdown report to OUTPUT_DIR. No LLM, no API key required —
this is a pure tool-layer integration check.

Permitted defaults:
  - DOMAIN target: example.com (passive lookups only)
  - SCAN target:   scanme.nmap.org (Nmap's public scan playground)

Override with env vars SMOKE_DOMAIN and SMOKE_SCAN_HOST if you have written
permission to test something else.
"""
import os
import sys
import time
from datetime import datetime

from recon import ReconAIAgent


def section(title: str, body: str) -> str:
    return f"\n## {title}\n\n```\n{body}\n```\n"


def timed(label: str, fn, *args, **kwargs):
    t0 = time.time()
    try:
        result = fn(*args, **kwargs)
        ok = True
    except Exception as e:
        result = f"EXCEPTION: {type(e).__name__}: {e}"
        ok = False
    dt = time.time() - t0
    flag = "OK " if ok else "ERR"
    print(f"  [{flag}] {label:<22} {dt:5.2f}s")
    return result, dt, ok


def main() -> int:
    domain = os.getenv("SMOKE_DOMAIN", "example.com")
    scan_host = os.getenv("SMOKE_SCAN_HOST", "scanme.nmap.org")

    print(f"Smoke test")
    print(f"  Passive target: {domain}")
    print(f"  Scan target:    {scan_host}")
    print()

    agent = ReconAIAgent()

    results = []

    whois_out, _, _ = timed("whois_lookup",       agent.whois_lookup, domain)
    dns_out,   _, _ = timed("dns_lookup",         agent.dns_lookup, domain)
    sub_out,   _, _ = timed("subdomain_enum",     agent.subdomain_enum, domain, 25)
    http_out,  _, _ = timed("http_fingerprint",   agent.http_fingerprint, domain)
    ssl_out,   _, _ = timed("ssl_inspect",        agent.ssl_inspect, domain)
    scan_out,  _, _ = timed("port_scan",          agent.port_scan, scan_host)

    # web_search is intentionally skipped: it hits a third-party (DDG) that
    # often rate-limits CI. Uncomment to include.
    # search_out, _, _ = timed("web_search",      agent.web_search, f"{domain} security")

    stamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    report_name = f"smoke_{domain.replace('.', '_')}_{stamp}.md"

    body = (
        f"# Recon smoke test — {domain}\n\n"
        f"Generated: {datetime.now().isoformat(timespec='seconds')}  \n"
        f"Passive target: `{domain}`  \n"
        f"Scan target:    `{scan_host}`\n"
        + section("whois_lookup",     whois_out)
        + section("dns_lookup",       dns_out)
        + section("subdomain_enum",   sub_out)
        + section("http_fingerprint", http_out)
        + section("ssl_inspect",      ssl_out)
        + section("port_scan",        scan_out)
    )

    write_msg = agent.write_file(report_name, body)
    print()
    print(write_msg)

    # Print the absolute path so the user can open it directly.
    abs_path = os.path.abspath(os.path.join(agent.working_directory, report_name))
    print(f"Report path: {abs_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
