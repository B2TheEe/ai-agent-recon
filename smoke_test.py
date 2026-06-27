"""
End-to-end smoke test for the recon agent toolkit.

Runs every tool sequentially against a permitted target, asserts that each
output looks sane (not just "no exception"), and writes a consolidated
markdown report to OUTPUT_DIR. No LLM, no API key required.

Modes:
  --passive   Only passive / query-only tools (CI-friendly).
  --active    Only active tools (sends real packets; needs permission).
  --all       Both (default).

Exit code is non-zero if any tool raised OR produced output that failed its
content assertion (e.g. an "Error: ..." string from a soft-fail path).

Permitted defaults:
  - DOMAIN target: example.com    (passive lookups only)
  - SCAN target:   scanme.nmap.org (Nmap's public scan playground)

Override with env vars SMOKE_DOMAIN and SMOKE_SCAN_HOST if you have written
permission to test something else.
"""
import argparse
import os
import re
import sys
import time
from datetime import datetime

from recon import ReconAIAgent


# ---------- result type ----------

class Result:
    __slots__ = ("name", "output", "dt", "ran_ok", "assertion_ok", "assertion_msg")

    def __init__(self, name: str, output: str, dt: float, ran_ok: bool,
                 assertion_ok: bool, assertion_msg: str):
        self.name = name
        self.output = output
        self.dt = dt
        self.ran_ok = ran_ok
        self.assertion_ok = assertion_ok
        self.assertion_msg = assertion_msg

    @property
    def passed(self) -> bool:
        return self.ran_ok and self.assertion_ok


# ---------- helpers ----------

def section(title: str, body: str) -> str:
    return f"\n## {title}\n\n```\n{body}\n```\n"


def _flag(r: Result) -> str:
    if not r.ran_ok:
        return "ERR"
    if not r.assertion_ok:
        return "BAD"
    return "OK "


def run(label: str, assertion, fn, *args, **kwargs) -> Result:
    """Run fn, time it, then check assertion(output) -> (bool, msg)."""
    t0 = time.time()
    ran_ok = True
    try:
        output = fn(*args, **kwargs)
    except Exception as e:
        output = f"EXCEPTION: {type(e).__name__}: {e}"
        ran_ok = False
    dt = time.time() - t0

    if ran_ok:
        try:
            assertion_ok, msg = assertion(output)
        except Exception as e:
            assertion_ok, msg = False, f"assertion crashed: {type(e).__name__}: {e}"
    else:
        assertion_ok, msg = False, "tool raised exception"

    r = Result(label, output, dt, ran_ok, assertion_ok, msg)
    suffix = "" if r.passed else f"  ← {msg}"
    print(f"  [{_flag(r):<3}] {label:<22} {dt:5.2f}s{suffix}")
    return r


# ---------- assertions ----------
# Each assertion returns (ok: bool, reason_if_not_ok: str).
# Permissive enough to pass legitimate runs, strict enough to catch silent
# regressions like soft "Error: ..." paths.

def _no_error_prefix(out: str) -> tuple[bool, str]:
    first = out.strip().splitlines()[0] if out.strip() else ""
    if first.lower().startswith("error:"):
        return False, f"output starts with {first!r}"
    return True, ""


def _contains(out: str, needles: list[str], label: str) -> tuple[bool, str]:
    missing = [n for n in needles if n not in out]
    if missing:
        return False, f"{label}: missing {missing}"
    return True, ""


def assert_whois(out: str) -> tuple[bool, str]:
    ok, why = _no_error_prefix(out)
    if not ok:
        return ok, why
    return _contains(out, ["WHOIS for", "Registrar"], "whois")


def assert_dns(out: str) -> tuple[bool, str]:
    ok, why = _no_error_prefix(out)
    if not ok:
        return ok, why
    # At minimum we expect an A record block for any live domain.
    if not re.search(r"^\s*A:\s*$", out, re.MULTILINE):
        return False, "no A: record block"
    return True, ""


def assert_subdomains(out: str) -> tuple[bool, str]:
    ok, why = _no_error_prefix(out)
    if not ok:
        return ok, why
    # crt.sh either returns subdomains or an explicit "no results" — both fine,
    # but a soft "Error: crt.sh returned HTTP 404" should fail.
    return True, ""


def assert_http_fp(out: str) -> tuple[bool, str]:
    ok, why = _no_error_prefix(out)
    if not ok:
        return ok, why
    if not re.search(r"Status:\s*[2345]\d\d", out):
        return False, "no HTTP status line"
    return True, ""


def assert_ssl(out: str) -> tuple[bool, str]:
    ok, why = _no_error_prefix(out)
    if not ok:
        return ok, why
    return _contains(out, ["Subject CN", "Valid to"], "ssl")


def assert_cve(out: str) -> tuple[bool, str]:
    ok, why = _no_error_prefix(out)
    if not ok:
        return ok, why
    if not re.search(r"CVE-\d{4}-\d+", out):
        return False, "no CVE-IDs found"
    return True, ""


def assert_port_scan(out: str) -> tuple[bool, str]:
    ok, why = _no_error_prefix(out)
    if not ok:
        return ok, why
    # scanme.nmap.org reliably has 22/tcp open. If user overrode SMOKE_SCAN_HOST,
    # they should still see *some* open port on a worthwhile target.
    if "Open: 0" in out:
        return False, "no open ports reported"
    if not re.search(r"\d+/tcp", out):
        return False, "no per-port line"
    return True, ""


def assert_dirb(out: str) -> tuple[bool, str]:
    ok, why = _no_error_prefix(out)
    if not ok:
        return ok, why
    if "Tested:" not in out:
        return False, "no 'Tested:' summary line"
    return True, ""


def assert_methods(out: str) -> tuple[bool, str]:
    ok, why = _no_error_prefix(out)
    if not ok:
        return ok, why
    # We expect at least the GET row from the active-probe block.
    if not re.search(r"\bGET\b\s+\d{3}", out):
        return False, "no GET probe result"
    return True, ""


def assert_vhost(out: str) -> tuple[bool, str]:
    ok, why = _no_error_prefix(out)
    if not ok:
        return ok, why
    # vhost summary line is present in successful runs.
    if "vhost" not in out.lower() and "host header" not in out.lower():
        return False, "output doesn't mention vhost/host header"
    return True, ""


def assert_svc_probe(out: str) -> tuple[bool, str]:
    ok, why = _no_error_prefix(out)
    if not ok:
        return ok, why
    if not re.search(r"\d+/tcp", out):
        return False, "no per-port probe line"
    return True, ""


# ---------- tool batteries ----------

def run_passive(agent, domain: str) -> list[Result]:
    return [
        run("whois_lookup",     assert_whois,      agent.whois_lookup, domain),
        run("dns_lookup",       assert_dns,        agent.dns_lookup, domain),
        run("subdomain_enum",   assert_subdomains, agent.subdomain_enum, domain, 25),
        run("http_fingerprint", assert_http_fp,    agent.http_fingerprint, domain),
        run("ssl_inspect",      assert_ssl,        agent.ssl_inspect, domain),
        run("cve_lookup",       assert_cve,        agent.cve_lookup, "openssh", "", 3),
    ]


def run_active(agent, scan_host: str) -> list[Result]:
    scan_url = f"http://{scan_host}"
    return [
        run("port_scan",             assert_port_scan, agent.port_scan, scan_host),
        run("directory_bruteforce",  assert_dirb,      agent.directory_bruteforce, scan_url),
        run("http_methods",          assert_methods,   agent.http_methods, scan_url),
        run("vhost_discovery",       assert_vhost,     agent.vhost_discovery, scan_host, scan_host),
        run("service_version_probe", assert_svc_probe, agent.service_version_probe, scan_host, [22, 80]),
    ]


# ---------- main ----------

def main() -> int:
    parser = argparse.ArgumentParser(description="Recon toolkit smoke test")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--passive", action="store_true", help="Run only passive / query-only tools")
    group.add_argument("--active",  action="store_true", help="Run only active tools (needs permission)")
    group.add_argument("--all",     action="store_true", help="Run both (default)")
    args = parser.parse_args()

    do_passive = args.passive or args.all or not (args.passive or args.active)
    do_active  = args.active  or args.all or not (args.passive or args.active)

    domain    = os.getenv("SMOKE_DOMAIN",    "example.com")
    scan_host = os.getenv("SMOKE_SCAN_HOST", "scanme.nmap.org")

    mode = "passive+active" if (do_passive and do_active) else ("passive" if do_passive else "active")
    print(f"Smoke test ({mode})")
    if do_passive:
        print(f"  Passive target: {domain}")
    if do_active:
        print(f"  Scan target:    {scan_host}")
    print()

    agent = ReconAIAgent()

    results: list[Result] = []
    if do_passive:
        results += run_passive(agent, domain)
    if do_active:
        results += run_active(agent, scan_host)

    stamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    tag = "all" if (do_passive and do_active) else ("passive" if do_passive else "active")
    report_name = f"smoke_{tag}_{domain.replace('.', '_')}_{stamp}.md"

    n_total  = len(results)
    n_pass   = sum(1 for r in results if r.passed)
    n_failed = n_total - n_pass

    header = (
        f"# Recon smoke test — {mode}\n\n"
        f"Generated: {datetime.now().isoformat(timespec='seconds')}  \n"
        + (f"Passive target: `{domain}`  \n" if do_passive else "")
        + (f"Scan target:    `{scan_host}`\n" if do_active else "")
        + f"\nSummary: **{n_pass}/{n_total} passed**"
        + (f", {n_failed} failed\n" if n_failed else "\n")
    )

    body = header + "".join(
        section(
            r.name + (f"  — FAILED: {r.assertion_msg}" if not r.passed else ""),
            r.output,
        )
        for r in results
    )

    write_msg = agent.write_file(report_name, body)
    print()
    print(write_msg)
    abs_path = os.path.abspath(os.path.join(agent.working_directory, report_name))
    print(f"Report path: {abs_path}")

    if n_failed:
        print(f"\nFAILED: {n_failed}/{n_total} tools did not meet assertions.")
        return 1
    print(f"\nAll {n_total} tools passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
