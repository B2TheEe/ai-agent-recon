"""whois_lookup, dns_lookup, subdomain_enum — passive recon over DNS+WHOIS."""
import json
import subprocess
import time

import dns.resolver
import httpx
import whois as whois_lib

from .utils import DomainNormalizerMixin


class WhoisDnsMixin(DomainNormalizerMixin):
    def whois_lookup(self, domain: str) -> str:
        domain = self._normalize_domain(domain)

        # Primary: python-whois library
        try:
            w = whois_lib.whois(domain)
            if w and (w.domain_name or w.registrar or w.creation_date):
                fields = [
                    ("Domain", w.domain_name),
                    ("Registrar", w.registrar),
                    ("Whois server", w.whois_server),
                    ("Creation date", w.creation_date),
                    ("Expiration date", w.expiration_date),
                    ("Updated date", w.updated_date),
                    ("Name servers", w.name_servers),
                    ("Status", w.status),
                    ("Emails", w.emails),
                    ("DNSSEC", w.dnssec),
                    ("Registrant name", w.name),
                    ("Registrant org", w.org),
                    ("Country", w.country),
                ]
                lines = [f"WHOIS for {domain} (via python-whois)"]
                for label, value in fields:
                    if value:
                        lines.append(f"  {label}: {value}")
                return "\n".join(lines)
        except Exception as e:
            primary_err = f"python-whois failed: {e}"
        else:
            primary_err = "python-whois returned no usable data"

        # Fallback: system `whois` CLI (handy for .nl / .eu)
        try:
            result = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                return (f"WHOIS for {domain} (via system whois)\n"
                        f"{result.stdout.strip()}")
            return (f"Error: {primary_err}; system whois "
                    f"exit={result.returncode} "
                    f"stderr={result.stderr.strip()}")
        except FileNotFoundError:
            return (f"Error: {primary_err}; system 'whois' command not "
                    "installed (try: sudo apt install whois)")
        except Exception as e:
            return f"Error: {primary_err}; system whois exception: {e}"

    def dns_lookup(self, domain: str,
                   record_types: list | None = None) -> str:
        domain = self._normalize_domain(domain)

        if not record_types:
            record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        lines = [f"DNS enumeration for {domain}"]
        for rtype in record_types:
            rtype_upper = rtype.upper()
            try:
                answers = resolver.resolve(domain, rtype_upper)
                lines.append(f"  {rtype_upper}:")
                for rdata in answers:
                    lines.append(f"    {rdata.to_text()}")
            except dns.resolver.NoAnswer:
                lines.append(f"  {rtype_upper}: (no records)")
            except dns.resolver.NXDOMAIN:
                return (f"DNS enumeration for {domain}\n"
                        "  Error: NXDOMAIN — domain does not exist")
            except dns.resolver.NoNameservers:
                lines.append(f"  {rtype_upper}: (no nameservers responded)")
            except dns.exception.Timeout:
                lines.append(f"  {rtype_upper}: (timeout)")
            except Exception as e:
                lines.append(f"  {rtype_upper}: error: {e}")
        return "\n".join(lines)

    def _query_crtsh(self, domain: str) -> tuple[set[str], str | None]:
        """Try crt.sh up to 2 times. Returns (subdomains, error_msg_if_failed)."""
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        last_err = "unknown error"
        for attempt in range(2):
            try:
                r = httpx.get(url, timeout=20.0, follow_redirects=True,
                              headers={"User-Agent": "ai-agent-recon/0.1"})
                # 404 / 429 / 5xx from crt.sh are usually transient — retry once.
                if r.status_code in (404, 429) or r.status_code >= 500:
                    last_err = f"HTTP {r.status_code}"
                    if attempt == 0:
                        time.sleep(1.0)
                        continue
                    return set(), f"crt.sh: {last_err} (after retry)"
                if r.status_code != 200:
                    return set(), f"crt.sh: HTTP {r.status_code}"
                data = r.json()
                subs: set[str] = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower().lstrip("*.")
                        if sub and (sub == domain or sub.endswith("." + domain)):
                            subs.add(sub)
                return subs, None
            except json.JSONDecodeError:
                last_err = "non-JSON (rate limit?)"
                if attempt == 0:
                    time.sleep(1.0)
                    continue
                return set(), f"crt.sh: {last_err}"
            except httpx.HTTPError as e:
                last_err = f"{type(e).__name__}: {e}"
                if attempt == 0:
                    time.sleep(1.0)
                    continue
                return set(), f"crt.sh: {last_err}"
        return set(), f"crt.sh: {last_err}"

    def _query_certspotter(self, domain: str) -> tuple[set[str], str | None]:
        """Fallback CT source: certspotter (no API key, free tier rate-limited)."""
        url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
               f"&include_subdomains=true&expand=dns_names")
        try:
            r = httpx.get(url, timeout=20.0, follow_redirects=True,
                          headers={"User-Agent": "ai-agent-recon/0.1"})
            if r.status_code == 429:
                return set(), "certspotter: rate limited (HTTP 429)"
            if r.status_code != 200:
                return set(), f"certspotter: HTTP {r.status_code}"
            data = r.json()
            subs: set[str] = set()
            for entry in data:
                for name in entry.get("dns_names", []):
                    name = name.strip().lower().lstrip("*.")
                    if name and (name == domain or name.endswith("." + domain)):
                        subs.add(name)
            return subs, None
        except json.JSONDecodeError:
            return set(), "certspotter: non-JSON response"
        except httpx.HTTPError as e:
            return set(), f"certspotter: {type(e).__name__}: {e}"

    def subdomain_enum(self, domain: str, limit: int = 100) -> str:
        domain = self._normalize_domain(domain)

        errors: list[str] = []
        sources_tried: list[str] = []

        # 1) crt.sh (primary)
        sources_tried.append("crt.sh")
        subs, err = self._query_crtsh(domain)
        source_used = "crt.sh"
        if err:
            errors.append(err)
            # 2) certspotter (fallback)
            sources_tried.append("certspotter")
            subs2, err2 = self._query_certspotter(domain)
            if err2:
                errors.append(err2)
                return ("Error: all CT sources failed:\n  "
                        + "\n  ".join(errors))
            subs = subs2
            source_used = "certspotter (crt.sh fallback)"

        if not subs:
            return (f"Subdomain enumeration for {domain} ({source_used})\n"
                    "  (no subdomains found)")

        sorted_subs = sorted(subs)
        truncated = len(sorted_subs) > limit
        shown = sorted_subs[:limit]
        lines = [f"Subdomain enumeration for {domain} ({source_used})",
                 f"  Sources tried: {', '.join(sources_tried)}",
                 f"  Found: {len(sorted_subs)} unique"
                 + (f", showing first {limit}" if truncated else "")]
        if errors and source_used != "crt.sh":
            lines.append(f"  Notes: {'; '.join(errors)}")
        for s in shown:
            lines.append(f"    {s}")
        return "\n".join(lines)
