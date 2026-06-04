"""
Unit tests for ReconAIAgent tools.

These mock every network call so the suite runs offline, deterministically,
and in <1 second — suitable for CI on every commit.

The live `smoke_test.py` complements this by exercising real endpoints
weekly via GitHub Actions.
"""
from __future__ import annotations

import json
import socket
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from recon import ReconAIAgent, TOP_100_TCP_PORTS, tools


# ----------------------------- fixtures -------------------------------------


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    return ReconAIAgent()


# ----------------------------- schema sanity --------------------------------


def test_tools_schema_loaded_from_json():
    assert isinstance(tools, list) and len(tools) >= 10
    names = {t["name"] for t in tools}
    expected = {"web_search", "whois_lookup", "dns_lookup", "subdomain_enum",
                "http_fingerprint", "port_scan", "ssl_inspect",
                "directory_bruteforce", "http_methods", "vhost_discovery",
                "write_file"}
    assert expected.issubset(names)
    for t in tools:
        assert "name" in t and "description" in t and "input_schema" in t
        assert t["input_schema"]["type"] == "object"


def test_top_100_ports_constant():
    assert len(TOP_100_TCP_PORTS) == 100
    assert all(1 <= p <= 65535 for p in TOP_100_TCP_PORTS)


# ----------------------------- _normalize_domain ----------------------------


@pytest.mark.parametrize("raw, expected", [
    ("example.com", "example.com"),
    ("EXAMPLE.COM", "example.com"),
    ("  example.com  ", "example.com"),
    ("https://example.com", "example.com"),
    ("http://example.com/path", "example.com"),
    ("https://example.com:8080/foo?bar=1", "example.com:8080"),
])
def test_normalize_domain(raw, expected):
    assert ReconAIAgent._normalize_domain(raw) == expected


# ----------------------------- whois_lookup ---------------------------------


def test_whois_lookup_happy_path(agent):
    fake = MagicMock()
    fake.domain_name = "EXAMPLE.COM"
    fake.registrar = "Test Registrar"
    fake.creation_date = "1995-08-14"
    fake.expiration_date = "2099-01-01"
    fake.whois_server = "whois.iana.org"
    fake.updated_date = None
    fake.name_servers = ["NS1.EXAMPLE.COM"]
    fake.status = None
    fake.emails = None
    fake.dnssec = "unsigned"
    fake.name = None
    fake.org = "Example Inc"
    fake.country = "US"

    with patch("recon.whois_lib.whois", return_value=fake):
        out = agent.whois_lookup("https://EXAMPLE.com/path")
    assert "WHOIS for example.com" in out
    assert "Test Registrar" in out
    assert "Example Inc" in out


def test_whois_lookup_library_fails_no_system_whois(agent):
    with patch("recon.whois_lib.whois", side_effect=Exception("boom")), \
         patch("recon.subprocess.run", side_effect=FileNotFoundError):
        out = agent.whois_lookup("example.com")
    assert "Error" in out
    assert "not installed" in out


# ----------------------------- dns_lookup -----------------------------------


def test_dns_lookup_aggregates_record_types(agent):
    import dns.resolver as _r

    def fake_resolve(name, rtype):
        if rtype == "A":
            rr = MagicMock()
            rr.to_text.return_value = "93.184.216.34"
            return [rr]
        if rtype == "MX":
            raise _r.NoAnswer()
        if rtype == "TXT":
            raise _r.NXDOMAIN()
        rr = MagicMock()
        rr.to_text.return_value = f"fake-{rtype}"
        return [rr]

    with patch("dns.resolver.Resolver") as MockResolver:
        instance = MockResolver.return_value
        instance.resolve.side_effect = fake_resolve
        out = agent.dns_lookup("example.com", record_types=["A", "MX", "TXT"])

    # NXDOMAIN on TXT short-circuits the function — we expect early return
    assert "NXDOMAIN" in out


def test_dns_lookup_no_nxdomain(agent):
    import dns.resolver as _r

    def fake_resolve(name, rtype):
        if rtype == "MX":
            raise _r.NoAnswer()
        rr = MagicMock()
        rr.to_text.return_value = f"value-{rtype}"
        return [rr]

    with patch("dns.resolver.Resolver") as MockResolver:
        instance = MockResolver.return_value
        instance.resolve.side_effect = fake_resolve
        out = agent.dns_lookup("example.com", record_types=["A", "MX"])

    assert "A:" in out and "value-A" in out
    assert "MX: (no records)" in out


# ----------------------------- subdomain_enum -------------------------------


def test_subdomain_enum_parses_crtsh(agent):
    sample = [
        {"name_value": "api.example.com\nwww.example.com"},
        {"name_value": "*.example.com"},
        {"name_value": "other.unrelated.org"},
        {"name_value": "API.EXAMPLE.COM"},  # duplicate, different case
    ]
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = sample
    with patch("recon.httpx.get", return_value=fake_response):
        out = agent.subdomain_enum("example.com")

    assert "api.example.com" in out
    assert "www.example.com" in out
    assert "example.com" in out  # bare apex from wildcard
    assert "other.unrelated.org" not in out
    # de-duplication: api.example.com appears once
    assert out.count("api.example.com") == 1


def test_subdomain_enum_handles_http_error(agent):
    fake_response = MagicMock(status_code=503)
    with patch("recon.httpx.get", return_value=fake_response):
        out = agent.subdomain_enum("example.com")
    assert "503" in out


# ----------------------------- http_fingerprint -----------------------------


def test_http_fingerprint_detects_tech_and_title(agent):
    fake_response = MagicMock()
    fake_response.url = "https://example.com/"
    fake_response.status_code = 200
    fake_response.reason_phrase = "OK"
    fake_response.http_version = "HTTP/2"
    fake_response.history = []
    fake_response.headers = {
        "server": "nginx/1.25",
        "content-type": "text/html",
        "strict-transport-security": "max-age=63072000",
    }
    fake_response.cookies.jar = []
    fake_response.text = "<html><head><title>Hello World</title></head></html>"

    client_cm = MagicMock()
    client_cm.__enter__.return_value.get.return_value = fake_response
    client_cm.__exit__.return_value = False

    with patch("recon.httpx.Client", return_value=client_cm):
        out = agent.http_fingerprint("example.com")

    assert "https://example.com" in out  # auto-prefixed
    assert "200 OK" in out
    assert "nginx" in out.lower()
    assert "Hello World" in out


# ----------------------------- port_scan ------------------------------------


def test_port_scan_resolves_and_reports(agent):
    """Mock asyncio.run and gethostbyname so no real packets are sent."""
    with patch("recon.socket.gethostbyname", return_value="1.2.3.4"), \
         patch.object(ReconAIAgent, "_run_scan", return_value=None), \
         patch("recon.asyncio.run", return_value=[(22, "SSH-2.0-Test"), (80, "")]):
        out = agent.port_scan("example.com", ports=[22, 80, 443])

    assert "1.2.3.4" in out
    assert "22/tcp" in out
    assert "ssh" in out  # service name via getservbyport
    assert "SSH-2.0-Test" in out
    assert "Open: 2" in out


def test_port_scan_dns_failure(agent):
    # Also stub _run_scan so the unused coroutine doesn't trigger a warning
    with patch("recon.socket.gethostbyname",
               side_effect=socket.gaierror("nope")), \
         patch.object(ReconAIAgent, "_run_scan", return_value=None), \
         patch("recon.asyncio.run"):
        out = agent.port_scan("does-not-exist.example")
    assert "DNS resolution" in out and "failed" in out


# ----------------------------- ssl_inspect ----------------------------------


def test_ssl_inspect_parses_cert(agent):
    now = datetime.now(timezone.utc)
    not_after = (now + timedelta(days=120)).strftime("%b %d %H:%M:%S %Y GMT")
    not_before = (now - timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")

    cert = {
        "subject": ((("commonName", "example.com"),),
                    (("organizationName", "Example Inc"),)),
        "issuer":  ((("commonName", "Test CA"),),),
        "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
        "notBefore": not_before,
        "notAfter": not_after,
        "serialNumber": "DEADBEEF",
        "version": 3,
    }

    fake_ssock = MagicMock()
    fake_ssock.getpeercert.return_value = cert
    fake_ssock.version.return_value = "TLSv1.3"
    fake_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    fake_ssock.__enter__.return_value = fake_ssock
    fake_ssock.__exit__.return_value = False

    fake_sock = MagicMock()
    fake_sock.__enter__.return_value = fake_sock
    fake_sock.__exit__.return_value = False

    fake_ctx = MagicMock()
    fake_ctx.wrap_socket.return_value = fake_ssock

    with patch("recon.ssl.create_default_context", return_value=fake_ctx), \
         patch("recon.socket.create_connection", return_value=fake_sock):
        out = agent.ssl_inspect("example.com")

    assert "TLSv1.3" in out
    assert "TLS_AES_256_GCM_SHA384" in out
    assert "example.com" in out
    assert "www.example.com" in out
    assert "DEADBEEF" in out
    assert "Days remaining: 119" in out or "Days remaining: 120" in out


# ----------------------------- write_file sandbox ---------------------------


def test_write_file_inside_sandbox(agent, tmp_path):
    msg = agent.write_file("sub/report.md", "hello")
    assert "Successfully" in msg
    assert (tmp_path / "sub" / "report.md").read_text() == "hello"


def test_write_file_rejects_path_traversal(agent):
    msg = agent.write_file("../../etc/evil", "x")
    assert msg.startswith("Error")
    assert "outside" in msg


# ----------------------------- directory_bruteforce -------------------------


def test_directory_bruteforce_filters_and_sorts(agent):
    fake_results = [
        ("admin", 200, 1234, ""),
        (".env", 200, 50, ""),
        ("nope", 404, 100, ""),       # filtered out
        ("redir", 301, 0, "/login"),
        ("forbidden", 403, 0, ""),
        ("crash", 500, 0, ""),
        ("not-tested", 418, 0, ""),   # filtered out (not in interesting set)
    ]
    with patch.object(ReconAIAgent, "_run_dirbrute", return_value=None), \
         patch("recon.asyncio.run", return_value=fake_results):
        out = agent.directory_bruteforce("example.com",
                                         paths=["a", "b", "c"])

    assert "https://example.com/" in out
    # 5 results pass the interesting_codes filter (200/200/301/403/500)
    assert "Interesting responses: 5" in out
    assert "404" not in out
    assert "418" not in out
    # 200s should appear before 403/500 (bucket sort)
    idx_200 = out.find("200 ")
    idx_403 = out.find("403 ")
    idx_500 = out.find("500 ")
    assert idx_200 < idx_403 < idx_500
    # Redirect Location preserved
    assert "-> /login" in out


def test_directory_bruteforce_no_hits(agent):
    with patch.object(ReconAIAgent, "_run_dirbrute", return_value=None), \
         patch("recon.asyncio.run", return_value=[]):
        out = agent.directory_bruteforce("example.com")
    assert "no high-signal responses" in out


# ----------------------------- http_methods ---------------------------------


def test_http_methods_flags_risky(agent):
    """OPTIONS Allow header is read, and PUT/DELETE/PATCH returning <400 are flagged RISKY."""
    responses = {
        "GET":     MagicMock(status_code=200, headers={}),
        "HEAD":    MagicMock(status_code=200, headers={}),
        "OPTIONS": MagicMock(status_code=200,
                             headers={"allow": "GET, HEAD, OPTIONS, PUT"}),
        "PUT":     MagicMock(status_code=200, headers={}),
        "DELETE":  MagicMock(status_code=405, headers={}),
        "PATCH":   MagicMock(status_code=200, headers={}),
        "TRACE":   MagicMock(status_code=405, headers={}),
    }

    def fake_request(method, url):
        return responses[method]

    fake_client = MagicMock()
    fake_client.request.side_effect = fake_request
    fake_client.__enter__.return_value = fake_client
    fake_client.__exit__.return_value = False

    with patch("recon.httpx.Client", return_value=fake_client):
        out = agent.http_methods("example.com")

    assert "https://example.com" in out
    # OPTIONS Allow header parsed
    assert "GET, HEAD, OPTIONS, PUT" in out
    # PUT returned 200 -> RISKY
    assert "PUT      200  [RISKY]" in out
    # DELETE returned 405 -> no marker
    assert "DELETE   405" in out
    # PATCH 200 -> RISKY
    assert "PATCH    200  [RISKY]" in out


def test_http_methods_no_allow_header(agent):
    responses = {m: MagicMock(status_code=403, headers={})
                 for m in ["GET", "HEAD", "OPTIONS", "PUT",
                          "DELETE", "PATCH", "TRACE"]}
    fake_client = MagicMock()
    fake_client.request.side_effect = lambda m, u: responses[m]
    fake_client.__enter__.return_value = fake_client
    fake_client.__exit__.return_value = False
    with patch("recon.httpx.Client", return_value=fake_client):
        out = agent.http_methods("example.com")
    assert "(not present)" in out
    assert "[RISKY]" not in out  # all 403 -> nothing flagged


# ----------------------------- vhost_discovery -----------------------------


def test_vhost_discovery_detects_anomaly(agent):
    """Baseline returns 404 / 100 bytes. One vhost returns 200 / 500 bytes — should be flagged."""
    baseline = MagicMock(status_code=404, content=b"x" * 100)

    fake_baseline_client = MagicMock()
    fake_baseline_client.get.return_value = baseline
    fake_baseline_client.__enter__.return_value = fake_baseline_client
    fake_baseline_client.__exit__.return_value = False

    # asyncio.run returns the list of (host, status, length) tuples
    fake_results = [
        ("admin.example.com", 200, 500),      # anomaly
        ("api.example.com",   404, 100),      # matches baseline
        ("dev.example.com",   404, 130),      # length diff < 50, ignored
        ("staging.example.com", 404, 200),    # length diff > 50, anomaly
    ]

    with patch("recon.httpx.Client", return_value=fake_baseline_client), \
         patch.object(ReconAIAgent, "_run_vhost", return_value=None), \
         patch("recon.asyncio.run", return_value=fake_results):
        out = agent.vhost_discovery("https://1.2.3.4", "example.com",
                                    hostnames=["admin", "api", "dev", "staging"])

    assert "Anomalies: 2" in out
    assert "admin.example.com" in out
    assert "staging.example.com" in out
    assert "api.example.com" not in out  # filtered (matches baseline exactly)


def test_vhost_discovery_baseline_failure(agent):
    fake_client = MagicMock()
    fake_client.get.side_effect = __import__("httpx").HTTPError("connect fail")
    fake_client.__enter__.return_value = fake_client
    fake_client.__exit__.return_value = False
    # _run_vhost stubbed even though baseline aborts early — prevents
    # the unused coroutine warning if the function ever changes
    with patch.object(ReconAIAgent, "_run_vhost", return_value=None), \
         patch("recon.httpx.Client", return_value=fake_client):
        out = agent.vhost_discovery("https://1.2.3.4", "example.com")
    assert "baseline request failed" in out
