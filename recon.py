import asyncio
import json
import os
import re
import socket
import subprocess
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
