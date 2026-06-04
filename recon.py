import asyncio
import json
import os
import re
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
import anthropic
import dns.resolver
import httpx
import whois as whois_lib
from ddgs import DDGS
from dotenv import load_dotenv
from prompts import system_prompt
load_dotenv()

# Single source of truth for tool schemas — loaded from tools.json
_TOOLS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools.json")
with open(_TOOLS_PATH, "r", encoding="utf-8") as _f:
    tools = json.load(_f)

# Builtin wordlist for directory_bruteforce — common high-value paths
DEFAULT_DIRECTORY_PATHS = [
    # dotfiles + VCS leaks
    ".env", ".env.local", ".env.production", ".git/config", ".git/HEAD",
    ".svn/entries", ".hg/hgrc", ".DS_Store", ".htaccess", ".htpasswd",
    "web.config",
    # backup / dumps
    "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "dump.sql",
    "database.sql", "site.tar.gz",
    # admin / auth
    "admin", "admin/", "admin/login", "administrator", "wp-admin/",
    "login", "signin", "auth", "console", "manage", "panel",
    # api / docs
    "api", "api/", "api/v1", "api/v2", "graphql", "swagger", "swagger-ui",
    "openapi.json", "api-docs", "redoc",
    # debug / status
    "debug", "test", "phpinfo.php", "info.php", "server-status",
    "server-info", "metrics", "health", "actuator", "actuator/env",
    # platform-specific
    "wp-config.php", "wp-login.php", "wp-json/", ".well-known/security.txt",
    # crawler / meta
    "robots.txt", "sitemap.xml", "crossdomain.xml", "humans.txt",
    # versioning
    "CHANGELOG", "CHANGELOG.md", "VERSION", "version.txt",
    # data dirs
    "uploads/", "files/", "data/", "logs/", "log/", "tmp/",
    "config/", "config.php", "config.json", "config.yml",
]

# Builtin wordlist for vhost_discovery — common subdomain prefixes
DEFAULT_VHOST_PREFIXES = [
    "admin", "administrator", "api", "app", "apps", "auth", "backup",
    "beta", "blog", "cdn", "ci", "cms", "cpanel", "dashboard", "db",
    "dev", "development", "demo", "docs", "files", "ftp", "git", "grafana",
    "internal", "intranet", "jenkins", "jira", "kibana", "log", "logs",
    "mail", "manage", "media", "mobile", "monitoring", "ns1", "ns2",
    "old", "panel", "portal", "preview", "private", "prod", "production",
    "qa", "redmine", "remote", "secure", "shop", "smtp", "ssh", "staging",
    "stats", "status", "store", "support", "test", "testing", "uat",
    "upload", "vpn", "webmail", "www", "www2", "wiki",
]

# nmap top-100 TCP ports (from nmap-services, ordered by frequency)
TOP_100_TCP_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
    49153, 49154, 49155, 49156, 49157,
]


class ReconAIAgent:
    def __init__(self):
        self.client = anthropic.Anthropic(
            api_key=os.getenv("ANTHROPIC_API_KEY")
        )
        self.working_directory = os.getenv("OUTPUT_DIR", "output")

    def web_search(self, query: str) -> str:
        results = DDGS().text(query=query, max_results=5)
        print(results)
        return str(results)

    def whois_lookup(self, domain: str) -> str:
        # Normalize: strip scheme/path if the model passed a URL
        domain = domain.strip().lower()
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.split("/")[0].split("?")[0]

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

        # Fallback: system `whois` CLI (e.g. handy for .nl / .eu)
        try:
            result = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                return f"WHOIS for {domain} (via system whois)\n{result.stdout.strip()}"
            return f"Error: {primary_err}; system whois exit={result.returncode} stderr={result.stderr.strip()}"
        except FileNotFoundError:
            return f"Error: {primary_err}; system 'whois' command not installed (try: sudo apt install whois)"
        except Exception as e:
            return f"Error: {primary_err}; system whois exception: {e}"

    def dns_lookup(self, domain: str, record_types: list | None = None) -> str:
        # Normalize input
        domain = domain.strip().lower()
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.split("/")[0].split("?")[0]

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
                return f"DNS enumeration for {domain}\n  Error: NXDOMAIN — domain does not exist"
            except dns.resolver.NoNameservers:
                lines.append(f"  {rtype_upper}: (no nameservers responded)")
            except dns.exception.Timeout:
                lines.append(f"  {rtype_upper}: (timeout)")
            except Exception as e:
                lines.append(f"  {rtype_upper}: error: {e}")
        return "\n".join(lines)

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        domain = domain.strip().lower()
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        return domain.split("/")[0].split("?")[0]

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
            return "Error: crt.sh returned non-JSON (likely rate limit or empty result)"
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
            return f"Subdomain enumeration for {domain}\n  (no subdomains found via crt.sh)"

        sorted_subs = sorted(subdomains)
        truncated = len(sorted_subs) > limit
        shown = sorted_subs[:limit]
        lines = [f"Subdomain enumeration for {domain} (crt.sh)",
                 f"  Found: {len(sorted_subs)} unique"
                 + (f", showing first {limit}" if truncated else "")]
        for s in shown:
            lines.append(f"    {s}")
        return "\n".join(lines)

    def http_fingerprint(self, target: str) -> str:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        interesting_headers = [
            "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
            "x-generator", "x-drupal-cache", "x-pingback", "via", "cf-ray",
            "content-type", "strict-transport-security", "content-security-policy",
            "x-frame-options", "x-content-type-options", "referrer-policy",
            "permissions-policy",
        ]

        try:
            with httpx.Client(timeout=15.0, follow_redirects=True,
                              headers={"User-Agent": "ai-agent-recon/0.1"},
                              verify=True) as client:
                r = client.get(target)
        except httpx.HTTPError as e:
            return f"Error: HTTP request failed: {e}"

        lines = [f"HTTP fingerprint for {target}",
                 f"  Final URL: {r.url}",
                 f"  Status: {r.status_code} {r.reason_phrase}",
                 f"  HTTP version: {r.http_version}"]

        if r.history:
            lines.append("  Redirect chain:")
            for hop in r.history:
                lines.append(f"    {hop.status_code} -> {hop.headers.get('location', '?')}")

        lines.append("  Headers of interest:")
        any_header = False
        for h in interesting_headers:
            if h in r.headers:
                lines.append(f"    {h}: {r.headers[h]}")
                any_header = True
        if not any_header:
            lines.append("    (none of the typical fingerprint headers were set)")

        cookies = [c.name for c in r.cookies.jar]
        if cookies:
            lines.append(f"  Cookies set: {', '.join(cookies)}")

        # Naive tech hints from cookies + headers
        hints = []
        cookie_blob = " ".join(cookies).lower()
        if "phpsessid" in cookie_blob: hints.append("PHP")
        if "asp.net" in cookie_blob or "x-aspnet-version" in r.headers: hints.append("ASP.NET")
        if "jsessionid" in cookie_blob: hints.append("Java (Servlet/JSP)")
        if "laravel_session" in cookie_blob: hints.append("Laravel")
        if "django" in cookie_blob: hints.append("Django")
        if "_rails" in cookie_blob or "rack.session" in cookie_blob: hints.append("Ruby on Rails")
        server = r.headers.get("server", "").lower()
        if "cloudflare" in server or "cf-ray" in r.headers: hints.append("Cloudflare (CDN/WAF)")
        if "nginx" in server: hints.append("nginx")
        if "apache" in server: hints.append("Apache httpd")
        if "iis" in server: hints.append("Microsoft IIS")
        if hints:
            lines.append(f"  Tech hints: {', '.join(sorted(set(hints)))}")

        # Title
        if "text/html" in r.headers.get("content-type", "").lower():
            m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
                lines.append(f"  Title: {title}")

        return "\n".join(lines)

    async def _scan_port(self, host: str, port: int, timeout: float,
                         sem: asyncio.Semaphore, banner: bool):
        async with sem:
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                return None

            banner_text = ""
            if banner:
                try:
                    # Some services (SSH, FTP, SMTP) speak first
                    data = await asyncio.wait_for(reader.read(128), timeout=0.8)
                    banner_text = data.decode("utf-8", errors="replace").strip()
                except (asyncio.TimeoutError, OSError):
                    banner_text = ""

            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass
            return (port, banner_text)

    async def _run_scan(self, host: str, ports: list, timeout: float,
                        concurrency: int, banner: bool):
        sem = asyncio.Semaphore(concurrency)
        tasks = [self._scan_port(host, p, timeout, sem, banner) for p in ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    def port_scan(self, host: str, ports: list | None = None,
                  timeout: float = 1.5, concurrency: int = 200,
                  banner: bool = True) -> str:
        host = self._normalize_domain(host)
        # Resolve once so we report what we actually scanned
        try:
            resolved = socket.gethostbyname(host)
        except socket.gaierror as e:
            return f"Error: DNS resolution for {host} failed: {e}"

        if not ports:
            ports = TOP_100_TCP_PORTS
        ports = sorted(set(int(p) for p in ports if 1 <= int(p) <= 65535))

        try:
            open_ports = asyncio.run(
                self._run_scan(host, ports, timeout, concurrency, banner)
            )
        except Exception as e:
            return f"Error: scan failed: {e}"

        lines = [f"TCP port scan for {host} ({resolved})",
                 f"  Scanned: {len(ports)} ports, timeout={timeout}s, concurrency={concurrency}",
                 f"  Open: {len(open_ports)}"]
        if not open_ports:
            lines.append("  (no open ports detected in scanned range)")
        else:
            for port, b in sorted(open_ports):
                svc = ""
                try:
                    svc = socket.getservbyport(port, "tcp")
                except OSError:
                    pass
                line = f"    {port}/tcp"
                if svc:
                    line += f"  {svc}"
                if b:
                    # Keep banner short, single line
                    short = re.sub(r"\s+", " ", b)[:120]
                    line += f"  banner=\"{short}\""
                lines.append(line)
        return "\n".join(lines)

    def ssl_inspect(self, host: str, port: int = 443) -> str:
        host = self._normalize_domain(host)
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    cipher = ssock.cipher()  # (name, protocol, bits)
        except (socket.gaierror, OSError, ssl.SSLError) as e:
            return f"Error: TLS handshake with {host}:{port} failed: {e}"

        def _flatten(name_tuples):
            # Each tuple is a tuple of (key, value) pairs
            return {k: v for entry in (name_tuples or ()) for k, v in entry}

        subject = _flatten(cert.get("subject"))
        issuer = _flatten(cert.get("issuer"))
        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

        # Validity parsing — stdlib gives "Mar 15 09:00:00 2025 GMT"
        fmt = "%b %d %H:%M:%S %Y %Z"
        try:
            not_before = datetime.strptime(cert["notBefore"], fmt).replace(tzinfo=timezone.utc)
            not_after = datetime.strptime(cert["notAfter"], fmt).replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (not_after - now).days
            expired = now > not_after
            not_yet_valid = now < not_before
        except (KeyError, ValueError):
            not_before = not_after = None
            days_left = None
            expired = not_yet_valid = False

        lines = [f"TLS certificate for {host}:{port}",
                 f"  Negotiated: {tls_version} / {cipher[0] if cipher else 'unknown'}"
                 + (f" ({cipher[2]} bits)" if cipher else "")]

        if subject.get("commonName"):
            lines.append(f"  Subject CN: {subject['commonName']}")
        if subject.get("organizationName"):
            lines.append(f"  Subject O:  {subject['organizationName']}")
        if issuer.get("commonName"):
            lines.append(f"  Issuer CN:  {issuer['commonName']}")
        if issuer.get("organizationName"):
            lines.append(f"  Issuer O:   {issuer['organizationName']}")

        if not_before and not_after:
            lines.append(f"  Valid from: {not_before.isoformat()}")
            lines.append(f"  Valid to:   {not_after.isoformat()}")
            if expired:
                lines.append(f"  Status: EXPIRED ({-days_left} days ago)")
            elif not_yet_valid:
                lines.append(f"  Status: NOT YET VALID")
            else:
                warning = "  WARNING: expires soon" if days_left is not None and days_left < 30 else ""
                lines.append(f"  Days remaining: {days_left}{warning}")

        if cert.get("serialNumber"):
            lines.append(f"  Serial: {cert['serialNumber']}")
        if cert.get("version"):
            lines.append(f"  Version: v{cert['version']}")

        if sans:
            lines.append(f"  SANs ({len(sans)}):")
            for s in sans[:20]:
                lines.append(f"    {s}")
            if len(sans) > 20:
                lines.append(f"    ... and {len(sans) - 20} more")

        return "\n".join(lines)

    # ---- directory_bruteforce ---------------------------------------------

    async def _try_path(self, client, base, path, sem):
        async with sem:
            try:
                r = await client.get(base + path)
                return (path, r.status_code, len(r.content),
                        r.headers.get("location", ""))
            except httpx.HTTPError:
                return None

    async def _run_dirbrute(self, base, paths, concurrency, timeout):
        sem = asyncio.Semaphore(concurrency)
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=False,
            headers={"User-Agent": "ai-agent-recon/0.1"}
        ) as client:
            tasks = [self._try_path(client, base, p, sem) for p in paths]
            results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    def directory_bruteforce(self, url: str, paths: list | None = None,
                             concurrency: int = 20,
                             timeout: float = 10.0) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        if not url.endswith("/"):
            url += "/"
        paths = paths or DEFAULT_DIRECTORY_PATHS
        interesting_codes = {200, 201, 204, 301, 302, 307, 401, 403, 500}

        try:
            results = asyncio.run(
                self._run_dirbrute(url, paths, concurrency, timeout)
            )
        except Exception as e:
            return f"Error: directory bruteforce failed: {e}"

        interesting = [r for r in results if r[1] in interesting_codes]
        lines = [f"Directory bruteforce for {url}",
                 f"  Tested: {len(paths)} paths, concurrency={concurrency}",
                 f"  Interesting responses: {len(interesting)}"]
        if not interesting:
            lines.append("  (no high-signal responses)")
        else:
            # Sort: 200s first (most interesting), then by code, then path
            def sort_key(item):
                code = item[1]
                bucket = 0 if code == 200 else (1 if code < 400 else 2)
                return (bucket, code, item[0])
            for path, code, length, loc in sorted(interesting, key=sort_key):
                line = f"    {code}  {length:>8} bytes  /{path}"
                if loc:
                    line += f"  -> {loc}"
                lines.append(line)
        return "\n".join(lines)

    # ---- http_methods -----------------------------------------------------

    def http_methods(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        methods_to_test = ["GET", "HEAD", "OPTIONS", "PUT", "DELETE",
                           "PATCH", "TRACE"]
        risky = {"PUT", "DELETE", "PATCH", "TRACE"}

        allowed_via_options: list[str] = []
        per_method: dict[str, object] = {}

        try:
            with httpx.Client(
                timeout=10.0, verify=False, follow_redirects=False,
                headers={"User-Agent": "ai-agent-recon/0.1"}
            ) as client:
                for method in methods_to_test:
                    try:
                        r = client.request(method, url)
                        per_method[method] = r.status_code
                        if method == "OPTIONS":
                            allow_hdr = r.headers.get("allow", "")
                            allowed_via_options = [
                                m.strip().upper()
                                for m in allow_hdr.split(",") if m.strip()
                            ]
                    except httpx.HTTPError as e:
                        per_method[method] = f"err: {type(e).__name__}"
        except Exception as e:
            return f"Error: HTTP methods test failed: {e}"

        lines = [f"HTTP methods test for {url}"]
        if allowed_via_options:
            lines.append(
                f"  OPTIONS Allow header: {', '.join(allowed_via_options)}"
            )
        else:
            lines.append("  OPTIONS Allow header: (not present)")
        lines.append("  Active probe results:")
        for method in methods_to_test:
            status = per_method.get(method, "?")
            marker = ""
            if isinstance(status, int) and status < 400:
                marker = "  [RISKY]" if method in risky else "  [OK]"
            lines.append(f"    {method:<8} {status}{marker}")
        return "\n".join(lines)

    # ---- vhost_discovery --------------------------------------------------

    async def _try_vhost(self, client, target, host, sem):
        async with sem:
            try:
                r = await client.get(target, headers={"Host": host})
                return (host, r.status_code, len(r.content))
            except httpx.HTTPError:
                return None

    async def _run_vhost(self, target, hosts, concurrency, timeout):
        sem = asyncio.Semaphore(concurrency)
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=False,
            headers={"User-Agent": "ai-agent-recon/0.1"}
        ) as client:
            tasks = [self._try_vhost(client, target, h, sem) for h in hosts]
            return await asyncio.gather(*tasks)

    def vhost_discovery(self, target: str, base_domain: str,
                        hostnames: list | None = None,
                        concurrency: int = 15,
                        timeout: float = 8.0) -> str:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        base_domain = self._normalize_domain(base_domain)
        prefixes = hostnames or DEFAULT_VHOST_PREFIXES
        full_hosts = [f"{p}.{base_domain}" for p in prefixes]

        # Establish a baseline with a deterministic bogus hostname
        bogus = f"recon-bogus-{abs(hash(base_domain)) % 10000}.invalid"
        try:
            with httpx.Client(
                timeout=timeout, verify=False, follow_redirects=False,
                headers={"User-Agent": "ai-agent-recon/0.1"}
            ) as client:
                r = client.get(target, headers={"Host": bogus})
                baseline_status = r.status_code
                baseline_length = len(r.content)
        except httpx.HTTPError as e:
            return f"Error: baseline request failed: {e}"

        try:
            results = asyncio.run(
                self._run_vhost(target, full_hosts, concurrency, timeout)
            )
        except Exception as e:
            return f"Error: vhost scan failed: {e}"

        # An anomaly = status differs OR content-length differs by >50 bytes
        hits = []
        for r in results:
            if not r:
                continue
            host, status, length = r
            if status != baseline_status or abs(length - baseline_length) > 50:
                hits.append((host, status, length))

        lines = [f"Virtual host discovery for {target}",
                 f"  Base domain: {base_domain}",
                 f"  Baseline (Host: {bogus}): "
                 f"status={baseline_status}, {baseline_length} bytes",
                 f"  Tested: {len(full_hosts)} vhosts",
                 f"  Anomalies: {len(hits)}"]
        for host, status, length in sorted(hits, key=lambda x: -x[2]):
            lines.append(
                f"    {host:<40}  status={status:<3}  {length} bytes"
            )
        return "\n".join(lines)

    # ---- service_version_probe -------------------------------------------

    # Ports that typically speak TLS — wrap socket before probing
    _TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443}
    # Ports that should receive an HTTP GET request
    _HTTP_PORTS = {80, 81, 591, 631, 1080, 2000, 3000, 5000, 5800, 7001,
                   8000, 8008, 8080, 8081, 8090, 8443, 8888, 9000, 9090,
                   9200, 9300, 10000}

    @staticmethod
    def _extract_version(banner: str, service_hint: str = "") -> str:
        """Pull a best-guess 'product version' string from a banner."""
        if not banner:
            return ""
        b = banner.strip()
        # SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
        m = re.match(r"SSH-\d+\.\d+-(\S+)", b)
        if m:
            return f"SSH/{m.group(1)}"
        # SMTP/POP3/IMAP/FTP greeting: "220 <host> ESMTP Postfix (Ubuntu)"
        m = re.match(r"^(\d{3})[ -](.+)", b.split("\n")[0])
        if m:
            return f"{service_hint or 'banner'}/{m.group(2).strip()[:120]}"
        # HTTP Server header
        m = re.search(r"^Server:\s*(.+?)\r?$", b, re.MULTILINE)
        if m:
            return f"HTTP/{m.group(1).strip()}"
        # Redis PONG: response to PING is "+PONG\r\n", INFO has "redis_version:X.Y.Z"
        m = re.search(r"redis_version:(\S+)", b)
        if m:
            return f"Redis/{m.group(1)}"
        # MySQL protocol: byte 5 is protocol version (10), then null-terminated server version
        # Banner shows up after a 4-byte header; just look for digits-dot pattern
        m = re.search(r"(\d+\.\d+\.\d+[\w.-]*)", b)
        if m and service_hint:
            return f"{service_hint}/{m.group(1)}"
        return ""

    async def _probe_port(self, host: str, port: int, timeout: float,
                          sem: asyncio.Semaphore):
        async with sem:
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                return (port, None, "(connection failed)")

            banner = ""
            service_hint = ""
            try:
                # 1) Read whatever the server speaks first (most banner protocols)
                try:
                    data = await asyncio.wait_for(reader.read(512),
                                                  timeout=1.0)
                    banner = data.decode("utf-8", errors="replace")
                except asyncio.TimeoutError:
                    banner = ""

                # 2) If nothing came back, send a protocol-specific probe
                if not banner.strip():
                    probe = None
                    if port in self._HTTP_PORTS:
                        probe = (f"GET / HTTP/1.0\r\nHost: {host}\r\n"
                                 "User-Agent: ai-agent-recon/0.1\r\n\r\n").encode()
                        service_hint = "HTTP"
                    elif port == 6379:  # Redis
                        probe = b"*1\r\n$4\r\nPING\r\n"
                        service_hint = "Redis"
                    elif port == 11211:  # memcached
                        probe = b"version\r\n"
                        service_hint = "memcached"

                    if probe:
                        writer.write(probe)
                        await writer.drain()
                        try:
                            data = await asyncio.wait_for(reader.read(1024),
                                                          timeout=timeout)
                            banner = data.decode("utf-8", errors="replace")
                        except asyncio.TimeoutError:
                            pass

                # 3) Service-aware EHLO for SMTP / STARTTLS-style ports
                if port in (25, 587, 465) and banner.startswith("220"):
                    service_hint = "SMTP"
                    try:
                        writer.write(b"EHLO recon.local\r\n")
                        await writer.drain()
                        more = await asyncio.wait_for(reader.read(2048),
                                                      timeout=1.5)
                        banner += "\n" + more.decode("utf-8", errors="replace")
                    except asyncio.TimeoutError:
                        pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except OSError:
                    pass

            # Service hint from well-known ports if we didn't set one
            if not service_hint:
                hints = {
                    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
                    443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL",
                    6379: "Redis", 9200: "Elasticsearch", 11211: "memcached",
                }
                service_hint = hints.get(port, "")

            version = self._extract_version(banner, service_hint)
            return (port, service_hint, version or banner.strip()[:150])

    async def _run_version_probe(self, host: str, ports: list,
                                 timeout: float, concurrency: int):
        sem = asyncio.Semaphore(concurrency)
        tasks = [self._probe_port(host, p, timeout, sem) for p in ports]
        return await asyncio.gather(*tasks)

    def service_version_probe(self, host: str, ports: list,
                              timeout: float = 4.0,
                              concurrency: int = 20) -> str:
        host = self._normalize_domain(host)
        try:
            resolved = socket.gethostbyname(host)
        except socket.gaierror as e:
            return f"Error: DNS resolution for {host} failed: {e}"

        ports = sorted(set(int(p) for p in ports if 1 <= int(p) <= 65535))
        if not ports:
            return f"Error: no valid ports provided"

        try:
            results = asyncio.run(
                self._run_version_probe(host, ports, timeout, concurrency)
            )
        except Exception as e:
            return f"Error: probe failed: {e}"

        lines = [f"Service version probe for {host} ({resolved})",
                 f"  Probed: {len(ports)} ports, timeout={timeout}s"]
        for port, service, info in sorted(results, key=lambda r: r[0]):
            svc = service or "?"
            line = f"    {port}/tcp  {svc:<8}"
            if info:
                short = re.sub(r"\s+", " ", info)[:140]
                line += f"  {short}"
            lines.append(line)
        return "\n".join(lines)

    # ---- cve_lookup -------------------------------------------------------

    @staticmethod
    def _parse_service_version(s: str):
        """Extract (product, version) from a probe info string.

        Handles 'X/Product/Version' (HTTP/Apache/2.4.7),
        'X/Product_Version' (SSH/OpenSSH_6.6.1p1),
        and 'Product/Version' (Redis/7.2.4).
        """
        if not s:
            return None
        # X/Product/Version  or  X/Product_Version
        m = re.match(r"^[^/]+/([A-Za-z][A-Za-z0-9]*)[_/]([\d][\d.]*[\w.-]*)",
                     s)
        if m:
            return (m.group(1), m.group(2))
        # Product/Version
        m = re.match(r"^([A-Za-z][A-Za-z0-9]*)/([\d][\d.]*[\w.-]*)", s)
        if m:
            return (m.group(1), m.group(2))
        return None

    @staticmethod
    def _extract_cvss(cve: dict):
        """Pull (score, severity) from an NVD CVE record, trying v4/v3.1/v3/v2."""
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31",
                    "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key, [])
            if arr:
                cvss = arr[0].get("cvssData", {})
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity", "")
                # CVSSv2 doesn't always include baseSeverity
                if score is not None and not severity:
                    if score >= 9.0:
                        severity = "CRITICAL"
                    elif score >= 7.0:
                        severity = "HIGH"
                    elif score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                return (score, severity)
        return (None, "")

    def cve_lookup(self, product: str, version: str = "",
                   limit: int = 5) -> str:
        if not product:
            return "Error: product is required"

        def _query(keyword: str):
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": min(max(int(limit), 1), 50),
            }
            try:
                r = httpx.get(url, params=params, timeout=20.0,
                              headers={"User-Agent": "ai-agent-recon/0.1"})
            except httpx.HTTPError as e:
                return None, f"NVD request failed: {e}"
            if r.status_code != 200:
                return None, f"NVD returned HTTP {r.status_code}"
            try:
                return r.json(), None
            except json.JSONDecodeError:
                return None, "NVD returned non-JSON response"

        keyword = f"{product} {version}".strip()
        data, err = _query(keyword)
        if err:
            return f"Error: {err}"

        retried = False
        if not data.get("vulnerabilities") and version:
            # Retry with product alone — NVD keywordSearch is whole-word,
            # so 'OpenSSH 6.6.1' often misses while 'OpenSSH' hits.
            retried = True
            time.sleep(0.5)  # be polite
            data, err = _query(product)
            if err:
                return f"Error: {err}"
            keyword = product

        vulns = data.get("vulnerabilities", [])
        total = data.get("totalResults", len(vulns))

        if not vulns:
            return f"CVE lookup: {keyword}\n  No CVEs found"

        entries = []
        for v in vulns:
            cve = v.get("cve", {})
            cid = cve.get("id", "?")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            score, severity = self._extract_cvss(cve)
            entries.append((score if score is not None else -1.0,
                            cid, severity, desc))

        # Sort by CVSS desc (None at end)
        entries.sort(key=lambda x: -x[0])

        header = f"CVE lookup: {keyword}"
        if retried:
            header += f" (retried — no results for '{product} {version}')"
        lines = [header,
                 f"  Total CVEs found: {total}, showing top "
                 f"{min(len(entries), limit)} by CVSS"]
        for score, cid, severity, desc in entries[:limit]:
            short_desc = re.sub(r"\s+", " ", desc).strip()[:180]
            if score >= 0:
                score_str = f"CVSS {score}"
                sev_str = f" {severity}" if severity else ""
            else:
                score_str = "CVSS n/a"
                sev_str = ""
            lines.append(f"    {cid} [{score_str}{sev_str}]  {short_desc}")
        return "\n".join(lines)

    # ---- recon_report -----------------------------------------------------

    def recon_report(self, host: str, skip_cve: bool = False) -> str:
        host = self._normalize_domain(host)
        sections = [
            f"# Recon Report — {host}",
            "",
            f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
            f"Target: `{host}`",
            "",
        ]

        # Stage 1: port_scan
        sections.append("## Port scan")
        sections.append("")
        port_scan_out = self.port_scan(host)
        sections.append("```")
        sections.append(port_scan_out)
        sections.append("```")
        sections.append("")

        # Parse open port numbers from the port_scan output
        open_ports = []
        for line in port_scan_out.splitlines():
            m = re.match(r"^\s+(\d+)/tcp", line)
            if m:
                open_ports.append(int(m.group(1)))

        if not open_ports:
            sections.append(
                "_No open ports detected — skipping service probe and CVE lookup._"
            )
            return "\n".join(sections)

        # Stage 2: service_version_probe
        sections.append(f"## Service versions ({len(open_ports)} ports)")
        sections.append("")
        probe_out = self.service_version_probe(host, open_ports)
        sections.append("```")
        sections.append(probe_out)
        sections.append("```")
        sections.append("")

        if skip_cve:
            sections.append("_CVE lookup skipped (skip_cve=true)._")
            return "\n".join(sections)

        # Stage 3: parse (product, version) tuples + CVE lookup
        services = []
        for line in probe_out.splitlines():
            m = re.match(r"^\s+(\d+)/tcp\s+(\S+)\s+(.+?)$", line)
            if not m:
                continue
            port = m.group(1)
            service = m.group(2)
            info = m.group(3).strip()
            if service == "?" or info.startswith("("):
                continue
            parsed = self._parse_service_version(info)
            if parsed:
                services.append((port, service, parsed[0], parsed[1]))

        if not services:
            sections.append("## CVEs")
            sections.append("")
            sections.append(
                "_No service versions could be parsed — nothing to look up._"
            )
            return "\n".join(sections)

        sections.append(f"## CVE lookup ({len(services)} services)")
        sections.append("")
        for i, (port, svc, product, version) in enumerate(services):
            sections.append(f"### {port}/tcp — {product} {version}")
            sections.append("")
            cve_out = self.cve_lookup(product, version, limit=5)
            sections.append("```")
            sections.append(cve_out)
            sections.append("```")
            sections.append("")
            # Gentle rate-limit between NVD calls (5 req / 30s unauthenticated)
            if i < len(services) - 1:
                time.sleep(1.0)

        return "\n".join(sections)

    # ---- write_file -------------------------------------------------------

    def write_file(self, file_path: str, content: str) -> str:
        abs_work = os.path.abspath(self.working_directory)
        abs_file = os.path.abspath(os.path.join(self.working_directory, file_path))

        if not abs_file.startswith(abs_work):
            return f'Error: Cannot write to "{file_path}" as it is outside the permitted working directory'

        if os.path.isdir(abs_file):
            return f'Error: Cannot write to "{file_path}" as it is a directory'

        try:
            dir_name = os.path.dirname(abs_file)
            if dir_name:
                os.makedirs(dir_name, exist_ok=True)
            with open(abs_file, "w", encoding="utf-8") as f:
                f.write(content)
            return f'Successfully wrote to "{file_path}" ({len(content)} characters written)'
        except Exception as e:
            return f'Error: {e}'

    def execute_tool(self, name: str, inputs: dict) -> str:
        if name == "web_search":
            return self.web_search(**inputs)
        if name == "whois_lookup":
            return self.whois_lookup(**inputs)
        if name == "dns_lookup":
            return self.dns_lookup(**inputs)
        if name == "subdomain_enum":
            return self.subdomain_enum(**inputs)
        if name == "http_fingerprint":
            return self.http_fingerprint(**inputs)
        if name == "port_scan":
            return self.port_scan(**inputs)
        if name == "ssl_inspect":
            return self.ssl_inspect(**inputs)
        if name == "directory_bruteforce":
            return self.directory_bruteforce(**inputs)
        if name == "http_methods":
            return self.http_methods(**inputs)
        if name == "vhost_discovery":
            return self.vhost_discovery(**inputs)
        if name == "service_version_probe":
            return self.service_version_probe(**inputs)
        if name == "cve_lookup":
            return self.cve_lookup(**inputs)
        if name == "recon_report":
            return self.recon_report(**inputs)
        if name == "write_file":
            return self.write_file(**inputs)
        return f'Error: Unknown tool "{name}"'

    def run_agent(self, user_query: str, max_iterations: int = 10) -> str:
        print(f"\n{'='*50}")
        print(f"User: {user_query}")
        print(f"{'='*50}")

        messages = [
            {"role": "user", "content": user_query}
        ]

        for iteration in range(max_iterations):
            print(f"\n[Iteration {iteration + 1}]")

            response = self.client.messages.create(
                model="claude-sonnet-4-5",
                max_tokens=4096,
                system=system_prompt,
                tools=tools,
                messages=messages
            )

            print(f"Stop reason: {response.stop_reason}")

            if response.stop_reason == "end_turn":
                final_answer = ""
                for block in response.content:
                    if hasattr(block, 'text'):
                        final_answer += block.text
                        print(f"\nFinal Answer: {final_answer}")
                return final_answer

            if response.stop_reason == "tool_use":
                messages.append({
                    "role": "assistant",
                    "content": response.content
                })

                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        print(f"  Tool: {block.name}")
                        print(f"  Input: {block.input}")

                        result = self.execute_tool(block.name, block.input)
                        print(f"  Result: {result}")

                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result
                        })

                messages.append({
                    "role": "user",
                    "content": tool_results
                })

        return "Max iterations reached without a final answer."


if __name__ == "__main__":
    agent = ReconAIAgent()
    query = input("On which company would you like to perform passive reconnaissance? ")
    agent.run_agent(user_query=query, max_iterations=10)
