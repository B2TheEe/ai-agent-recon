"""whois_lookup, dns_lookup, subdomain_enum — passive recon over DNS+WHOIS."""
import json
import subprocess

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

    def subdomain_enum(self, domain: str, limit: int = 100) -> str:
        domain = self._normalize_domain(domain)
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            r = httpx.get(url, timeout=20.0, follow_redirects=True,
                          headers={"User-Agent": "ai-agent-recon/0.1"})
            if r.status_code != 200:
                return f"Error: crt.sh returned HTTP {r.status_code}"
            data = r.json()
        except json.JSONDecodeError:
            return ("Error: crt.sh returned non-JSON "
                    "(likely rate limit or empty result)")
        except httpx.HTTPError as e:
            return f"Error: HTTP request to crt.sh failed: {e}"

        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower().lstrip("*.")
                if sub and (sub == domain or sub.endswith("." + domain)):
                    subdomains.add(sub)

        if not subdomains:
            return (f"Subdomain enumeration for {domain}\n"
                    "  (no subdomains found via crt.sh)")

        sorted_subs = sorted(subdomains)
        truncated = len(sorted_subs) > limit
        shown = sorted_subs[:limit]
        lines = [f"Subdomain enumeration for {domain} (crt.sh)",
                 f"  Found: {len(sorted_subs)} unique"
                 + (f", showing first {limit}" if truncated else "")]
        for s in shown:
            lines.append(f"    {s}")
        return "\n".join(lines)
