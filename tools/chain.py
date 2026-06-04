"""recon_report — end-to-end chainer.

Orchestrates port_scan -> service_version_probe -> cve_lookup per service
and renders the result as a single markdown document.
"""
import re
import time
from datetime import datetime, timezone

from .utils import DomainNormalizerMixin


class ChainMixin(DomainNormalizerMixin):
    def recon_report(self, host: str, skip_cve: bool = False) -> str:
        host = self._normalize_domain(host)
        sections = [
            f"# Recon Report — {host}",
            "",
            (f"Generated: "
             f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}"),
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

        open_ports = []
        for line in port_scan_out.splitlines():
            m = re.match(r"^\s+(\d+)/tcp", line)
            if m:
                open_ports.append(int(m.group(1)))

        if not open_ports:
            sections.append(
                "_No open ports detected — skipping service probe "
                "and CVE lookup._"
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
                "_No service versions could be parsed — "
                "nothing to look up._"
            )
            return "\n".join(sections)

        sections.append(f"## CVE lookup ({len(services)} services)")
        sections.append("")
        for i, (port, _svc, product, version) in enumerate(services):
            sections.append(f"### {port}/tcp — {product} {version}")
            sections.append("")
            cve_out = self.cve_lookup(product, version, limit=5)
            sections.append("```")
            sections.append(cve_out)
            sections.append("```")
            sections.append("")
            # Gentle rate-limit between NVD calls (5 req/30s unauthenticated)
            if i < len(services) - 1:
                time.sleep(1.0)

        return "\n".join(sections)
