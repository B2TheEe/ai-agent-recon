"""HTTP / TLS tools — fingerprinting, certs, dir bruteforce, methods, vhosts."""
import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone

import httpx

from .constants import DEFAULT_DIRECTORY_PATHS, DEFAULT_VHOST_PREFIXES
from .utils import DomainNormalizerMixin


class HttpMixin(DomainNormalizerMixin):
    # ---- http_fingerprint -------------------------------------------------

    def http_fingerprint(self, target: str) -> str:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        interesting_headers = [
            "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
            "x-generator", "x-drupal-cache", "x-pingback", "via", "cf-ray",
            "content-type", "strict-transport-security",
            "content-security-policy", "x-frame-options",
            "x-content-type-options", "referrer-policy", "permissions-policy",
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
                lines.append(
                    f"    {hop.status_code} -> "
                    f"{hop.headers.get('location', '?')}"
                )

        lines.append("  Headers of interest:")
        any_header = False
        for h in interesting_headers:
            if h in r.headers:
                lines.append(f"    {h}: {r.headers[h]}")
                any_header = True
        if not any_header:
            lines.append(
                "    (none of the typical fingerprint headers were set)"
            )

        cookies = [c.name for c in r.cookies.jar]
        if cookies:
            lines.append(f"  Cookies set: {', '.join(cookies)}")

        # Naive tech hints from cookies + headers
        hints = []
        cookie_blob = " ".join(cookies).lower()
        if "phpsessid" in cookie_blob:
            hints.append("PHP")
        if "asp.net" in cookie_blob or "x-aspnet-version" in r.headers:
            hints.append("ASP.NET")
        if "jsessionid" in cookie_blob:
            hints.append("Java (Servlet/JSP)")
        if "laravel_session" in cookie_blob:
            hints.append("Laravel")
        if "django" in cookie_blob:
            hints.append("Django")
        if "_rails" in cookie_blob or "rack.session" in cookie_blob:
            hints.append("Ruby on Rails")
        server = r.headers.get("server", "").lower()
        if "cloudflare" in server or "cf-ray" in r.headers:
            hints.append("Cloudflare (CDN/WAF)")
        if "nginx" in server:
            hints.append("nginx")
        if "apache" in server:
            hints.append("Apache httpd")
        if "iis" in server:
            hints.append("Microsoft IIS")
        if hints:
            lines.append(f"  Tech hints: {', '.join(sorted(set(hints)))}")

        # Title
        if "text/html" in r.headers.get("content-type", "").lower():
            m = re.search(r"<title[^>]*>(.*?)</title>",
                          r.text, re.IGNORECASE | re.DOTALL)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
                lines.append(f"  Title: {title}")

        return "\n".join(lines)

    # ---- ssl_inspect ------------------------------------------------------

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
            return {k: v for entry in (name_tuples or ()) for k, v in entry}

        subject = _flatten(cert.get("subject"))
        issuer = _flatten(cert.get("issuer"))
        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

        fmt = "%b %d %H:%M:%S %Y %Z"
        try:
            not_before = datetime.strptime(cert["notBefore"], fmt) \
                .replace(tzinfo=timezone.utc)
            not_after = datetime.strptime(cert["notAfter"], fmt) \
                .replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (not_after - now).days
            expired = now > not_after
            not_yet_valid = now < not_before
        except (KeyError, ValueError):
            not_before = not_after = None
            days_left = None
            expired = not_yet_valid = False

        lines = [
            f"TLS certificate for {host}:{port}",
            f"  Negotiated: {tls_version} / "
            f"{cipher[0] if cipher else 'unknown'}"
            + (f" ({cipher[2]} bits)" if cipher else ""),
        ]

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
                lines.append("  Status: NOT YET VALID")
            else:
                warning = ("  WARNING: expires soon"
                           if days_left is not None and days_left < 30
                           else "")
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

        hits = []
        for r in results:
            if not r:
                continue
            host, status, length = r
            if (status != baseline_status
                    or abs(length - baseline_length) > 50):
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
