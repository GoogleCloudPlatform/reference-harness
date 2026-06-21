---
name: xss
description: Detects XSS via disabled template autoescape, unsanitized input in views, or HTML construction from user input
when_to_apply: Codebase renders HTML server-side (any view templating: Swig, Jinja, EJS, Pug, ERB, Razor) OR serves dynamic HTML responses
file_globs: server.js, app.js, **/views/**, **/templates/**, **/routes/**, **/*.html, **/*.ejs, **/*.pug
---

# XSS: Detection Procedure

## What this is

User-controlled input is rendered into HTML/JS without escaping, letting an
attacker inject scripts that execute in another user's browser. OWASP A3 /
CWE-79.

## Where to look — TWO levels matter

1.  **Architectural root cause** — the template engine's escape policy in the
    app setup.
1.  **Per-site symptoms** — specific views or response handlers that bypass
    escaping.

The root-cause finding is often more valuable: disabling autoescape globally
creates XSS in every view at once.

## How to find it

### Root-cause check (do this first)

1.  `grep_code` for template-engine config in app setup:

- `autoescape\s*:\s*false`
- `autoescape\s*=\s*False`
- `escapeMarkup\s*:\s*false`
- `noEscape|disableHTMLEscape`

1.  If found, `read_code_window` to confirm it's in app/server config
    (server.js, app.js, main.py).

### Symptom check

1.  `grep_code` for unescaped output patterns in templates:

- `\{\{\{.*\}\}\}` (Handlebars/Mustache triple-stash = raw HTML)
- `\|safe\b` (Jinja `|safe` filter)
- `\|raw\b` (Twig `|raw` filter)
- `\{!.*!\}` (Pug unescaped interpolation)
- `dangerouslySetInnerHTML` (React)
- `\.innerHTML\s*=` (DOM, if SSR)

1.  `grep_code` for direct response construction:

- `res\.send\(.*req\.` (Node: user data in response body)
- `res\.write\(.*req\.`

1.  For each hit, `read_code_window` to verify user data flows in unsanitized.

## True-positive signals

- `autoescape: false` (or framework equivalent) in app config — count as a
  single finding for the whole app.
- Unescaped interpolation of `req.*` / `request.*` data into HTML response.

## False-positive signals (do NOT flag)

- `|safe` used on a server-rendered, hardcoded HTML constant (not user data).
- `dangerouslySetInnerHTML` with sanitized output (DOMPurify, sanitize-html,
  etc.) — verify the sanitizer call is present.
- API endpoint that returns JSON only (no HTML rendering — JSON serializers
  escape by default).

## Output: severity guidance

- **Critical** for stored XSS (input persisted, served to other users).
- **High** for reflected XSS on authenticated pages or globally-disabled
  autoescape.
- **Medium** for self-XSS or admin-only contexts.

## Output: CWE

- `CWE-79` (Improper Neutralization of Input During Web Page Generation)

## Output: rule_id slug

- `ai.xss-autoescape-disabled` (root cause)
- `ai.xss-stored` (specific stored XSS path)
- `ai.xss-reflected` (specific reflected XSS path)
