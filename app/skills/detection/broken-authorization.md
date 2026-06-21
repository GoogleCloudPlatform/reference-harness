---
name: broken-authorization
description: Detects missing function-level access control — admin-only or role-restricted features reachable by any authenticated user
when_to_apply: Codebase has role-based features (admin panels, benefits/HR routes, account-management endpoints, billing)
file_globs: server.js, app.js, **/routes/**, **/middleware/**, **/auth/**
---

# Broken Authorization (Missing Function-Level Access Control): Detection Procedure

## What this is

A route is intended to be admin-only (or role-restricted), but the route handler
only checks "is this user logged in?" — not "is this user actually allowed to
use this feature?" OWASP A7 / CWE-285, CWE-862.

## Where to look

1.  Central route registration (server.js, app.js, routes/index.js, urls.py) —
    which routes get which middleware?
1.  Files named `benefits`, `admin`, `billing`, `users-admin`, `settings`,
    `audit-logs`.
1.  Any route whose intended audience is "internal" or "ops only".

## How to find it

1.  `grep_code` for the auth middleware definitions to learn what's available:

- `function\s+is(Logged\s*In|Admin|Authenticated|Authorized)`
- `def\s+(login_required|admin_required)`
- `@(login_required|admin_required)`

1.  `grep_code` for route registrations, looking for asymmetric middleware:

- `app\.(post|put|delete)\s*\(['"][^'"]+['"]\s*,\s*isLoggedIn` (note: NO isAdmin
  after)
- `router\.(post|put|delete)\s*\(.*[^,]\s*,\s*[a-zA-Z_]+Handler` (only one
  middleware)

1.  **Pay close attention to commented-out role checks** — same smoking-gun
    pattern as commented-out CSRF middleware:

- `//\s*isAdmin`
- `//\s*admin_required`

1.  For each suspicious route, `read_code_window` to:

- See the registered middleware chain.
- Read the route handler — does it do its own role check internally?
- Find a known-admin-only feature (benefits, user management) and see whether
  the route guard matches.

## True-positive signals

- An admin-only feature route is registered with `isLoggedIn` only, no
  `isAdmin`.
- A role check (`isAdmin`, `hasRole('admin')`) is commented out adjacent to the
  route registration.
- The route handler reads/writes data from a model that other code paths gate
  behind admin checks.

## False-positive signals (do NOT flag)

- The route is genuinely accessible to all authenticated users by design.
- The handler performs the role check internally (verify by reading the handler
  body).
- Granular RBAC middleware (e.g. `requirePermission('benefits.edit')`) is
  present even if it doesn't look like a typical `isAdmin`.

## Output: severity guidance

- **High** for admin-only writes accessible to any logged-in user.
- **Critical** if the feature exposes financial / compliance / PII data.
- **Medium** for read-only admin pages reachable by regular users.

## Output: CWE

- `CWE-285` (Improper Authorization)
- `CWE-862` (Missing Authorization)
- `CWE-732` (Incorrect Permission Assignment for Critical Resource — when
  role-check is commented out)

## Output: rule_id slug

- `ai.broken-authz`
- `ai.missing-admin-check`
