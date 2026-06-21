---
name: idor
description: Detects Insecure Direct Object Reference — record IDs from the URL used to fetch data without verifying ownership/authorization
when_to_apply: Codebase has authenticated routes that fetch user-scoped data (allocations, profiles, orders, documents, messages) by ID
file_globs: **/routes/**, **/controllers/**, **/handlers/**, **/api/**
---

# IDOR: Detection Procedure

## What this is

The application reads a record key (user id, document id, account id) from the
URL or request body and queries the database with it — without verifying the
authenticated user is actually allowed to see that record. OWASP A4 / CWE-639.

## Where to look

1.  GET/PUT/DELETE routes with a numeric or UUID-ish path parameter that names
    an entity (`/allocations/:userId`, `/profile/:id`, `/orders/:orderId`).
1.  Routes that take an `id`, `userId`, `accountId`, `documentId` from
    `req.body` and act on it.

## How to find it

1.  `grep_code` for route param extraction patterns:

- `req\.params\.(userId|userid|id|accountId|orgId)`
- `req\.body\.(userId|userid|id|accountId|orgId)`
- `request\.match_info\[['"](user_)?id['"]\]` (aiohttp)
- `pk\s*=\s*request\.GET` (Django patterns)

1.  For each hit, `read_code_window` to find the matching DB query and ask:

- Does the handler **also** verify `req.session.userId == req.params.userId` (or
  equivalent) before querying?
- Does the query include a `WHERE owner_id = current_user.id` filter?

1.  Compare against well-implemented routes in the same codebase to see the
    contrast.

## True-positive signals

- Handler reads an id from `req.params` / `req.body` and queries the DB using
  that id directly, with NO ownership check.
- The session already contains the authenticated user's id, so using
  `req.params.userId` is gratuitously dangerous (the safe pattern is to use
  `req.session.userId` for owned-resource lookups).
- Sequential / guessable IDs (incrementing integers, MongoDB ObjectId) make
  exploitation trivial.

## False-positive signals (do NOT flag)

- The handler has an explicit
  `if (req.session.userId !== req.params.userId) return 403` or RBAC middleware
  that scopes by ownership.
- The id is a high-entropy unguessable token used as a capability (object
  capability pattern), AND the URL is not predictable/leakable.
- The route is genuinely public (e.g., a published-blog-post lookup by id).

## Output: severity guidance

- **High** for IDOR on user-private data (PII, financial, messages).
- **Critical** if combined with admin-only data exposure or write access.
- **Medium** for low-sensitivity records (e.g., public bookmark counts).

## Output: CWE

- `CWE-639` (Authorization Bypass Through User-Controlled Key)
- `CWE-285` (Improper Authorization, more general)

## Output: rule_id slug

- `ai.idor`
- `ai.idor-write` (if the handler also writes/deletes based on the unauthorized
  id)
