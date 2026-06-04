# Recon smoke test — anthropic.com

Generated: 2026-06-04T19:08:46  
Passive target: `anthropic.com`  
Scan target:    `scanme.nmap.org`

## whois_lookup

```
Error: python-whois failed: [Errno 104] Connection reset by peer; system 'whois' command not installed (try: sudo apt install whois)
```

## dns_lookup

```
DNS enumeration for anthropic.com
  A:
    160.79.104.10
  AAAA:
    2607:6bc0::10
  MX:
    10 alt4.aspmx.l.google.com.
    5 alt1.aspmx.l.google.com.
    10 alt3.aspmx.l.google.com.
    5 alt2.aspmx.l.google.com.
    1 aspmx.l.google.com.
  NS:
    randy.ns.cloudflare.com.
    isla.ns.cloudflare.com.
  TXT: (timeout)
  SOA:
    isla.ns.cloudflare.com. dns.cloudflare.com. 2406016715 10000 2400 604800 1800
  CNAME: (no records)
```

## subdomain_enum

```
Error: crt.sh returned HTTP 502
```

## http_fingerprint

```
HTTP fingerprint for https://anthropic.com
  Final URL: https://www.anthropic.com/
  Status: 200 OK
  HTTP version: HTTP/1.1
  Redirect chain:
    302 -> https://www.anthropic.com/
  Headers of interest:
    server: cloudflare
    cf-ray: a0688a93ccb6b8e1-AMS
    content-type: text/html; charset=utf-8
    strict-transport-security: max-age=3600
    content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.intellimize.co https://cdnjs.cloudflare.com https://d3e54v103j8qbb.cloudfront.net https://cdn.prod.website-files.com https://hubspotonwebflow.com https://www.googletagmanager.com https://a-cdn.anthropic.com https://connect.facebook.net https://www.youtube.com https://cdn.jsdelivr.net https://cdn.finsweet.com https://maps.googleapis.com https://js.hsforms.net https://player.vimeo.com; style-src 'self' 'unsafe-inline' https://cdn.prod.website-files.com https://cdnjs.cloudflare.com https://fonts.googleapis.com; img-src 'self' data: https://cdn.sanity.io https://www-cdn.anthropic.com https://cdn.prod.website-files.com https://img.youtube.com https://i.ytimg.com https://www.facebook.com https://maps.googleapis.com https://maps.gstatic.com https://www.googletagmanager.com https://forms-na1.hsforms.com; frame-src 'self' https://www.youtube-nocookie.com https://www.youtube.com https://cdn.embedly.com https://*.intellimizeio.com https://anthropic.swoogo.com https://*.hsforms.com https://*.hubspot.com; connect-src 'self' blob: https://cdn.intellimize.co https://api.intellimize.co https://log.intellimize.co https://cdn.sanity.io https://links.iterable.com https://a-cdn.anthropic.com https://a-api.anthropic.com https://www.facebook.com https://www.google-analytics.com https://cdn.prod.website-files.com https://hubspotonwebflow.com https://maps.googleapis.com https://vimeo.com https://www.googletagmanager.com https://code.claude.com https://forms.hsforms.com https://hubspot-forms-static-embed.s3.amazonaws.com https://cdnjs.cloudflare.com https://www.gstatic.com; media-src 'self' https://cdn.sanity.io; worker-src 'self' blob:; font-src 'self' data: https://cdn.prod.website-files.com https://fonts.gstatic.com; object-src 'none'; frame-ancestors 'self'; base-uri 'self'
  Cookies set: __cf_bm, _cfuvid
  Tech hints: Cloudflare (CDN/WAF)
  Title: Home \ Anthropic
```

## ssl_inspect

```
TLS certificate for anthropic.com:443
  Negotiated: TLSv1.3 / TLS_AES_256_GCM_SHA384 (256 bits)
  Subject CN: anthropic.com
  Issuer CN:  E8
  Issuer O:   Let's Encrypt
  Valid from: 2026-04-07T15:34:43+00:00
  Valid to:   2026-07-06T15:34:42+00:00
  Days remaining: 31
  Serial: 05D5D573B358D78ED6B3C8DECD35D46B5A1D
  Version: v3
  SANs (3):
    anthropic.com
    console-staging.anthropic.com
    console.anthropic.com
```

## port_scan

```
TCP port scan for scanme.nmap.org (45.33.32.156)
  Scanned: 100 ports, timeout=1.5s, concurrency=200
  Open: 2
    22/tcp  ssh  banner="SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
    80/tcp  http
```
