---
name: unvalidated-redirects
description: Detects open-redirect vulnerabilities — redirect target URLs taken from request parameters without allowlist validation
when_to_apply: Codebase has redirect-issuing routes (auth callbacks, post-login destinations, OAuth flows, "next" / "returnUrl" patterns, generic /learn or /go redirectors)
file_globs: **/routes/**, **/controllers/**, **/auth/**, **/middleware/**
---

# Unvalidated Redirects: Detection Procedure

## What this is

A route reads a target URL from the request (typically `?url=` or `?next=`) and
passes it directly to a redirect response. Attackers craft a link to the
legitimate site that redirects to an attacker-controlled site for phishing.
OWASP A10 / CWE-601.

## Where to look

1.  Auth callback routes, `?next`, `?returnUrl`, `?redirect`, `?continue`
    parameters.
1.  Routes named `/learn`, `/go`, `/out`, `/track`, `/redirect`, `/click`,
    `/share`.
1.  Post-login handlers that send the user back to "where they came from."

## How to find it

1.  `grep_code` for redirect sinks taking request data:

- `res\.redirect\s*\(\s*req\.(query|body|params)\.`
- `res\.redirect\s*\(.*\+\s*req\.`
- `return\s+redirect\s*\(\s*request\.` (Python)
- `return\s+RedirectResponse\s*\(.*request\.` (FastAPI)

1.  For each hit, `read_code_window` and check:

- Is the redirect URL passed unmodified, OR is there a
  `url.parse(target).host in ALLOWED_HOSTS` check?
- Is the URL forced to a relative path (e.g.,
  `target.startsWith('/') && !target.startsWith('//')`)?

## True-positive signals

- `res.redirect(req.query.url)` or equivalent, with no validation between.
- A redirect helper function that accepts arbitrary URLs.
- Auth flow uses an unvalidated `?next` param and the redirect happens after a
  successful login (worse — adds credential-phishing value).

## False-positive signals (do NOT flag)

- The target is allow-list-checked: `if (ALLOWED.includes(target.host))` before
  redirect.
- The target is forced to be a relative path (rejecting `//evil.com` /
  `http://...`).
- The redirect uses a server-side map (e.g., `redirects[req.query.id]`) where
  ids are not URLs.

## Output: severity guidance

- **Medium** in most cases — exploit is phishing, not direct compromise.
- **High** when combined with auth flows (login completion redirect, OAuth
  callback) where credential phishing is enabled.

## Output: CWE

- `CWE-601` (URL Redirection to Untrusted Site / Open Redirect)

## Output: rule_id slug

- `ai.unvalidated-redirect`
- `ai.open-redirect-in-auth-flow` (for the auth-coupled variant)
