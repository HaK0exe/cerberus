# SSRF protections (web scanner)

**Status: planned for Sprint 2** (`internal/scanner/web`). This
document specifies the required control before any web-crawling code
is merged; treat it as an acceptance-criteria checklist for that work,
not a description of code that exists yet.

## Required control flow

```text
URL parsing
     ↓
DNS resolution
     ↓
IP validation
     ↓
HTTP request
     ↓
redirect?
     ↓ yes
DNS/IP validation again (repeat for every hop)
```

Every redirect hop must be re-validated — validating only the initial
URL and then following redirects with a standard HTTP client is not
sufficient (classic redirect-based SSRF / DNS rebinding bypass).

## Default-blocked ranges

```text
127.0.0.0/8       10.0.0.0/8        172.16.0.0/12
192.168.0.0/16    169.254.0.0/16    ::1
fc00::/7          fe80::/10
```

Special case, always blocked regardless of the ranges above:
`169.254.169.254` (cloud instance metadata endpoint — AWS/GCP/Azure).

## robots.txt

`respect_robots_txt` defaults to `true`. `--ignore-robots` is an
explicit, non-default opt-in and must print:

```text
WARNING: robots.txt restrictions disabled
```

## Required tests before this is considered done

- SSRF to loopback/link-local/RFC1918 addresses directly in the URL
- SSRF via a redirect chain to a blocked address
- SSRF via DNS rebinding (resolves to public IP on first check, private
  IP on connect)
- Access to `169.254.169.254` specifically
- Oversized response body / decompression bomb via `Content-Encoding`
- Infinite/adversarial crawl (redirect loops, unbounded depth)

See the "Sprint 2" milestone in the issue tracker for the concrete
tickets tracking this work.
