"""TCP recon — port_scan + service_version_probe (async, banner-grab capable)."""
import asyncio
import re
import socket

from .constants import TOP_100_TCP_PORTS
from .utils import DomainNormalizerMixin


class TcpMixin(DomainNormalizerMixin):
    # Ports that typically speak TLS — wrap socket before probing
    _TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443}
    # Ports that should receive an HTTP GET request
    _HTTP_PORTS = {80, 81, 591, 631, 1080, 2000, 3000, 5000, 5800, 7001,
                   8000, 8008, 8080, 8081, 8090, 8443, 8888, 9000, 9090,
                   9200, 9300, 10000}

    # ---- port_scan --------------------------------------------------------

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
                    data = await asyncio.wait_for(reader.read(128),
                                                  timeout=0.8)
                    banner_text = data.decode("utf-8",
                                              errors="replace").strip()
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
        tasks = [self._scan_port(host, p, timeout, sem, banner)
                 for p in ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    def port_scan(self, host: str, ports: list | None = None,
                  timeout: float = 1.5, concurrency: int = 200,
                  banner: bool = True) -> str:
        host = self._normalize_domain(host)
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
                 f"  Scanned: {len(ports)} ports, timeout={timeout}s, "
                 f"concurrency={concurrency}",
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
                    short = re.sub(r"\s+", " ", b)[:120]
                    line += f"  banner=\"{short}\""
                lines.append(line)
        return "\n".join(lines)

    # ---- service_version_probe -------------------------------------------

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
            return (f"{service_hint or 'banner'}/"
                    f"{m.group(2).strip()[:120]}")
        # HTTP Server header
        m = re.search(r"^Server:\s*(.+?)\r?$", b, re.MULTILINE)
        if m:
            return f"HTTP/{m.group(1).strip()}"
        # Redis: INFO output has "redis_version:X.Y.Z"
        m = re.search(r"redis_version:(\S+)", b)
        if m:
            return f"Redis/{m.group(1)}"
        # Generic numeric version pattern as last fallback
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
                # 1) Read whatever the server speaks first
                try:
                    data = await asyncio.wait_for(reader.read(512),
                                                  timeout=1.0)
                    banner = data.decode("utf-8", errors="replace")
                except asyncio.TimeoutError:
                    banner = ""

                # 2) If nothing came back, send protocol-specific probe
                if not banner.strip():
                    probe = None
                    if port in self._HTTP_PORTS:
                        probe = (f"GET / HTTP/1.0\r\nHost: {host}\r\n"
                                 "User-Agent: ai-agent-recon/0.1\r\n\r\n"
                                 ).encode()
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
                            data = await asyncio.wait_for(
                                reader.read(1024), timeout=timeout
                            )
                            banner = data.decode("utf-8", errors="replace")
                        except asyncio.TimeoutError:
                            pass

                # 3) SMTP EHLO for STARTTLS-style ports
                if port in (25, 587, 465) and banner.startswith("220"):
                    service_hint = "SMTP"
                    try:
                        writer.write(b"EHLO recon.local\r\n")
                        await writer.drain()
                        more = await asyncio.wait_for(reader.read(2048),
                                                      timeout=1.5)
                        banner += "\n" + more.decode("utf-8",
                                                     errors="replace")
                    except asyncio.TimeoutError:
                        pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except OSError:
                    pass

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
            return "Error: no valid ports provided"

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
