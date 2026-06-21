---
name: sql-or-nosql-injection
description: Detects SQL/NoSQL injection via unsafe query construction (string concat, template interpolation, $where with user input)
when_to_apply: Codebase queries a database (any SQL DB, MongoDB, DynamoDB, Cassandra, Redis). Almost always applies.
file_globs: **/data/**, **/dao/**, **/models/**, **/repositories/**, **/db/**, **/queries/**, **/routes/**
---

# SQL/NoSQL Injection: Detection Procedure

## What this is

Untrusted input is concatenated/interpolated into a query without
parameterization, letting an attacker change the query's structure. OWASP A1 /
CWE-89 (SQL), CWE-943 (NoSQL).

## Where to look

1.  **Data-access modules** (`data/`, `dao/`, `repositories/`, `models/`) —
    where queries are constructed.
1.  **Route handlers** that build queries inline.

## How to find it

1.  `grep_code` for SQL sink patterns:

- `\.query\(.*\+` (string concat into query)
- `\.execute\(.*\$\{` (template-literal interpolation)
- `\.raw\(.*\+|\.raw\(.*\$\{`
- `f"SELECT.*\{|f'SELECT.*\{` (Python f-strings into SQL)

1.  `grep_code` for NoSQL sink patterns:

- `\$where[^:]*:` (MongoDB `$where` is JS eval — very dangerous if not constant)
- `\.find\(\s*\{[^}]*req\.` (request data flowing into find filters)
- `new\s+Function\(.*query` (dynamic function from query input)

1.  **For each hit, `read_code_window` to confirm**:

- Is the interpolated value reachable from user input (req.body, req.params,
  req.query, request.GET, etc.)?
- Is there NO `parameterize`, `prepared`, `?` placeholder, or library-native
  binding nearby?

1.  Trace one level back: if the value comes from a variable, find where it's
    assigned.

## True-positive signals

- A query string contains `+` or template interpolation AND the interpolated
  value flows from request data.
- MongoDB `$where` value is a string built from `req.*` data (allows arbitrary
  JS injection into the DB engine).
- Direct `eval` of query strings.

## False-positive signals (do NOT flag)

- Query uses parameterized binding (`?` placeholders,
  `db.query(sql, [arg1, arg2])`, `pymongo` filter dicts where values are not
  query operators).
- Interpolated value is a constant or a server-side enum, not user-controlled.
- ORM call with positional/named parameter binding (Sequelize `replacements`,
  SQLAlchemy `text(...).bindparams(...)`).

## Output: severity guidance

- **Critical** if the route is unauthenticated or any-authenticated-user
  reachable AND the query touches sensitive data.
- **High** for authenticated-only routes with sensitive data.
- **Medium** for harder-to-reach paths or limited-impact tables.

## Output: CWE

- `CWE-89` (SQL Injection)
- `CWE-943` (Improper Neutralization of Special Elements in Data Query Logic /
  NoSQL)

## Output: rule_id slug

- `ai.sql-injection`
- `ai.nosql-injection`
- `ai.mongo-where-injection` (for the specific `$where` pattern)
