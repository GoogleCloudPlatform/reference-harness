---
name: csrf
description: Detects missing CSRF protection on state-changing routes (commented-out csurf middleware, missing token validation, no SameSite enforcement)
when_to_apply: Codebase has form-handling POST/PUT/DELETE routes in a web framework (Express, Koa, Hapi, Fastify, Flask, Django, FastAPI, Rails)
file_globs: server.js, app.js, **/routes/**, **/middleware/**, **/views/**/*.html
---

# CSRF: Detection Procedure

## What this is

Cross-Site Request Forgery (OWASP A8 / CWE-352). State-changing requests from an
authenticated user can be forged by an attacker because the server doesn't
verify a per-session, per-form token.

## Where to look

1.  **The app's middleware setup** (server.js, app.js, src/index.ts, main.py,
    etc.) — does it register csurf / csrf-protect / Django CsrfViewMiddleware /
    Flask-WTF / etc.?
1.  **State-changing route handlers** (POST/PUT/DELETE) — do they pull a CSRF
    token from the request and validate it?
1.  **Form templates** — do form bodies include a hidden CSRF token field?

## How to find it

1.  `grep_code` for these patterns to find middleware registration:

- `require\(['"](csurf|csrf|csrf-protect)['"]`
- `app\.use\(.*(csrf|csurf|helmet)`
- `import.*from\s+['"](csurf|csrf)['"]`

1.  **Commented-out middleware is a smoking gun.** `grep_code` with:

- `//\s*app\.use\(.*(csrf|csurf|helmet)`
- `#\s*app\.use\(.*(csrf|csurf)`

1.  If middleware is referenced but commented out, `read_code_window` around the
    comment block to confirm — often you'll find an OWASP comment like
    `// Fix for A8 - CSRF` indicating it was deliberately disabled for the demo.
1.  If middleware appears to be wired, check that state-changing routes actually
    have CSRF check by inspecting at least one POST handler.

## True-positive signals

- `csurf` / `csrf` package imported AND `app.use(csrf())` is commented out,
  deleted, or never called.
- POST routes lack any token verification AND no global middleware enforces it.
- Cookies set without `sameSite: 'strict' | 'lax'` AND no token-based CSRF
  defense.
- Explicit comment like `// disabled CSRF`, `// TODO re-enable csurf`.

## False-positive signals (do NOT flag)

- App is purely a JSON API consumed by SPAs with bearer tokens AND uses no
  cookie-based session auth (CSRF doesn't apply).
- A framework with auto-CSRF defaults is in use (Django with default settings,
  Rails with `protect_from_forgery`) AND nothing disables it.
- The route in question is GET-only (read-only side-effect-free).

## Output: severity guidance

- **High** if commented-out / missing middleware on an authenticated app with
  cookie sessions and state-changing routes.
- **Medium** if partial protection (some routes covered, others not) or weak
  SameSite-only defense.
- **Low** if only theoretical (e.g., a single non-impactful endpoint).

## Output: CWE

- `CWE-352` (Cross-Site Request Forgery)

## Output: rule_id slug

- `ai.csrf-disabled` (when middleware is commented out / missing globally)
- `ai.csrf-route-unprotected` (when a specific state-changing route lacks
  per-route protection)
