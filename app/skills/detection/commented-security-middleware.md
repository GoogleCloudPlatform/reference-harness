---
name: commented-security-middleware
description: Detects security middleware (CSRF, security headers, rate limiting, CORS) that is imported but commented out / never registered
when_to_apply: Web frameworks with middleware-stack registration (Express, Koa, Fastify, Flask, Django, FastAPI). Run early in the discovery pass — it's quick and high-signal.
file_globs: server.js, app.js, src/index.ts, main.py, **/middleware/**
---

# Commented / Disabled Security Middleware: Detection Procedure

## What this is

A cross-cutting pattern: developer imports a security library (csurf, helmet,
express-rate-limit, cors) but the `app.use(...)` call is commented out, deleted,
or never made. This indicates the protection was deliberately disabled (often
"temporarily for debugging" — and forgotten) or was an aspirational TODO that
never landed.

## Why it deserves its own skill

This pattern is high-signal because:

- It's grep-detectable in seconds.
- The intent is unambiguous (developer KNEW they needed it).
- It often coexists with other findings whose severity it amplifies (XSS becomes
  much worse without helmet's CSP; brute-force is trivial without rate-limit).

## Where to look

1.  App entry point (server.js, app.js, src/index.ts, main.py) — where the
    middleware stack is built.
1.  Middleware setup helper files.

## How to find it

1.  `grep_code` for security library imports:

- `require\s*\(\s*['"](csurf|csrf|helmet|express-rate-limit|cors|express-mongo-sanitize|hpp)['"]`
- `from\s+['"](csurf|helmet|cors)['"]`
- `import\s+(csurf|helmet|cors)`

1.  `grep_code` for commented-out registrations:

- `^\s*//\s*app\.use\s*\(.*(csurf|csrf|helmet|cors|rateLimit|limiter|mongoSanitize|hpp)`
- `^\s*#\s*app\.use\s*\(.*(csurf|helmet|cors)`

1.  For each commented-out match, `read_code_window` to:

- Confirm the comment is in the live app setup (not a comment in a test or doc).
- Look for nearby explanatory comments (often something like
  `// disabled for local dev`, `// TODO re-enable`, `// Fix for A8 - CSRF`).

## True-positive signals

- A library is imported (`require('csurf')`) but `app.use(csurf())` is commented
  out or absent.
- A block of `app.use(...)` lines, all commented out, near a comment naming the
  OWASP issue.
- `helmet()` not registered when the app serves user-influenced HTML.

## False-positive signals (do NOT flag)

- The library is imported only to call a non-middleware helper.
- The framework provides equivalent protection by default (Django's CSRF
  middleware is on by default and may not need an explicit `app.use`).
- The commented-out code is part of a test scaffold or feature-flag wrapper
  that's controlled at runtime.

## Output: severity guidance

- **High** when CSRF, helmet (security headers), or rate-limit are disabled on a
  public, authenticated app.
- **Medium** for CORS misconfig (depends on what's exposed).
- **Low** for `hpp` or `mongo-sanitize` (defense-in-depth, less critical to
  have).

## Output: CWE

- `CWE-352` (CSRF, when csurf is the disabled lib)
- `CWE-693` (Protection Mechanism Failure — general)
- `CWE-1188` (Insecure Default Initialization of Resource)

## Output: rule_id slug

- `ai.csrf-disabled` (when csurf is the disabled lib)
- `ai.security-headers-disabled` (when helmet is disabled)
- `ai.rate-limit-disabled` (when express-rate-limit is disabled)
- `ai.security-middleware-commented` (generic)

## Cross-references to other skills

- If `csurf` is the disabled lib, ALSO consider the `csrf` skill for the
  per-route view.
- If `helmet` is disabled, the `xss` skill becomes more relevant (no
  Content-Security-Policy backstop).
