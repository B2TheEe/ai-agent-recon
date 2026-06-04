"""cve_lookup — NIST NVD CVE search by product + version."""
import json
import re
import time

import httpx


class VulnMixin:
    @staticmethod
    def _parse_service_version(s: str):
        """Extract (product, version) from a probe info string.

        Handles 'X/Product/Version' (HTTP/Apache/2.4.7),
        'X/Product_Version' (SSH/OpenSSH_6.6.1p1),
        and 'Product/Version' (Redis/7.2.4).
        """
        if not s:
            return None
        m = re.match(r"^[^/]+/([A-Za-z][A-Za-z0-9]*)[_/]"
                     r"([\d][\d.]*[\w.-]*)", s)
        if m:
            return (m.group(1), m.group(2))
        m = re.match(r"^([A-Za-z][A-Za-z0-9]*)/([\d][\d.]*[\w.-]*)", s)
        if m:
            return (m.group(1), m.group(2))
        return None

    @staticmethod
    def _extract_cvss(cve: dict):
        """Pull (score, severity) from an NVD CVE record.

        Prefers CVSS v4 > v3.1 > v3.0 > v2. Fills in severity heuristically
        when v2 omits baseSeverity.
        """
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31",
                    "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key, [])
            if arr:
                cvss = arr[0].get("cvssData", {})
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity", "")
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
            # NVD keywordSearch is whole-word, so 'OpenSSH 6.6.1p1' often
            # misses while 'OpenSSH' alone hits. Retry with product only.
            retried = True
            time.sleep(0.5)
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
