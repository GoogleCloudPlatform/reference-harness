---
name: ssrf
description: Detects server-side request forgery — user-controlled URLs passed to outbound HTTP clients without allowlist validation
when_to_apply: Codebase makes outbound HTTP requests (needle, axios, fetch, requests, urllib, httpx) potentially using URLs from user input
file_globs: **/routes/**, **/controllers/**, **/services/**, **/handlers/**, **/*.js, **/*.ts, **/*.py
---

# SSRF: Detection Procedure

## What this is

The server fetches a URL provided by the user. Attacker uses this to: read
internal/cloud-metadata services (169.254.169.254, localhost, private IPs),
proxy to internal services, scan internal network, or exfiltrate via DNS.
CWE-918.

## Where to look

1.  Routes that take a `url`, `link`, `target`, `webhook`, `callback`,
    `image_url`, `feed`, `endpoint`, `symbol`-like parameter.
1.  Functions that proxy, preview, fetch metadata, render thumbnails, or follow
    webhooks.

## How to find it

1.  `grep_code` for outbound HTTP client patterns:

- `needle\.(get|post|head)\s*\(`
- `axios\.(get|post|head|request)\s*\(`
- `fetch\s*\(`
- `requests\.(get|post|head|request)\s*\(` (Python)
- `urllib\.(request\.urlopen|urlopen)\s*\(`
- `httpx\.(get|post|request)\s*\(`

1.  For each hit, `read_code_window` and check:

- Is the URL argument built from `req.query.*`, `req.body.*`, `req.params.*`,
  `request.*`?
- Is there a host allowlist check, scheme check, or DNS-pin step BEFORE the
  call?

1.  Bonus pattern: `url\s*=\s*req\.` followed by a fetch call in the same
    function.

## True-positive signals

- URL string is concatenated or interpolated from `req.*` and then passed
  directly to an HTTP client.
- No `URL.parse(...).host in allowlist` or equivalent check.
- The route description / variable names suggest it's a proxy / webhook /
  preview.

## False-positive signals (do NOT flag)

- URL is a fixed constant or template with a fixed host (e.g.,
  `https://api.internal/v1/${id}` where id is path-component-only and the host
  is hardcoded).
- An explicit allowlist is checked before the call.
- The request goes to a known-safe public API with the user input only as a path
  parameter or query string of an external service (still worth lowering
  severity, not removing).

## Output: severity guidance

- **High** if request URL host is fully user-controlled — attacker can hit any
  host.
- **Medium** if host is fixed but a sensitive path component is user-controlled.
- **Low** for pure path-only injection into a known-safe public host.

## Output: CWE

- `CWE-918` (Server-Side Request Forgery)

## Output: rule_id slug

- `ai.ssrf`
- `ai.ssrf-cloud-metadata` (if you can show the path reaches a
  metadata-service-style host)
