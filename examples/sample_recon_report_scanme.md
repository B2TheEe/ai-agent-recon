# Recon Report — scanme.nmap.org

Generated: 2026-06-04T17:58:32+00:00
Target: `scanme.nmap.org`

## Port scan

```
TCP port scan for scanme.nmap.org (45.33.32.156)
  Scanned: 100 ports, timeout=1.5s, concurrency=200
  Open: 2
    22/tcp  ssh  banner="SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
    80/tcp  http
```

## Service versions (2 ports)

```
Service version probe for scanme.nmap.org (45.33.32.156)
  Probed: 2 ports, timeout=4.0s
    22/tcp  SSH       SSH/OpenSSH_6.6.1p1
    80/tcp  HTTP      HTTP/Apache/2.4.7 (Ubuntu)
```

## CVE lookup (2 services)

### 22/tcp — OpenSSH 6.6.1p1

```
CVE lookup: OpenSSH (retried — no results for 'OpenSSH 6.6.1p1')
  Total CVEs found: 158, showing top 5 by CVSS
    CVE-1999-0661 [CVSS 10.0 CRITICAL]  A system is running a version of software that was replaced with a Trojan Horse at one of its distribution points, such as (1) TCP Wrappers 7.6, (2) util-linux 2.9g, (3) wuarchive 
    CVE-2000-0525 [CVSS 10.0 CRITICAL]  OpenSSH does not properly drop privileges when the UseLogin option is enabled, which allows local users to execute arbitrary commands by providing the command to the ssh daemon.
    CVE-2000-1169 [CVSS 7.5 HIGH]  OpenSSH SSH client before 2.3.0 does not properly disable X11 or agent forwarding, which could allow a malicious SSH server to gain access to the X11 display and sniff X11 events, 
    CVE-2001-1459 [CVSS 7.5 HIGH]  OpenSSH 2.9 and earlier does not initiate a Pluggable Authentication Module (PAM) session if commands are executed with no pty, which allows local users to bypass resource limits (
    CVE-2000-0535 [CVSS 5.0 MEDIUM]  OpenSSL 0.9.4 and OpenSSH for FreeBSD do not properly check for the existence of the /dev/random or /dev/urandom devices, which are absent on FreeBSD Alpha systems, which causes th
```

### 80/tcp — Apache 2.4.7

```
CVE lookup: Apache 2.4.7
  Total CVEs found: 4, showing top 4 by CVSS
    CVE-2016-6814 [CVSS 9.8 CRITICAL]  When an application with unsupported Codehaus versions of Groovy from 1.7.0 to 2.4.3, Apache Groovy 2.4.4 to 2.4.7 on classpath uses standard Java serialization mechanisms, e.g. to
    CVE-2021-44224 [CVSS 8.2 HIGH]  A crafted URI sent to httpd configured as a forward proxy (ProxyRequests on) can cause a crash (NULL pointer dereference) or, for configurations mixing forward and reverse proxy de
    CVE-2025-66200 [CVSS 5.4 MEDIUM]  mod_userdir+suexec bypass via AllowOverride FileInfo vulnerability in Apache HTTP Server. Users with access to use the RequestHeader directive in htaccess can cause some CGI script
    CVE-2012-2378 [CVSS 4.3 MEDIUM]  Apache CXF 2.4.5 through 2.4.7, 2.5.1 through 2.5.3, and 2.6.x before 2.6.1, does not properly enforce child policies of a WS-SecurityPolicy 1.1 SupportingToken policy on the clien
```
