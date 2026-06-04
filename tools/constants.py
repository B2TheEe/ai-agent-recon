"""Shared constants — wordlists, port lists, and other lookup tables."""

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
