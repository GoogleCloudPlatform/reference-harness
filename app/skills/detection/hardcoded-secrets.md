---
name: hardcoded-secrets
description: Detects hardcoded credentials, API keys, JWT secrets, cookie signing keys, and other secrets committed in source/config
when_to_apply: Any codebase. Especially relevant for files in config/, src/, .env*, and route handlers.
file_globs: config/**, **/config/**, **/*.env*, **/*.js, **/*.ts, **/*.py, **/*.yaml, **/*.yml, **/*.json
---

# Hardcoded Secrets: Detection Procedure

## What this is

A secret value (password, API key, JWT signing key, OAuth client secret, cookie
secret, encryption key) is embedded literally in source code or non-secret
config, making it visible to anyone with repo access and unrotatable without a
code change. CWE-798, CWE-259.

## Where to look

1.  `config/` directories — especially `default`, `production`, `all.js`-style
    files.
1.  Anywhere with a `secret`, `key`, `token`, `password`, `apiKey` variable.
1.  Constants files (`constants.js`, `settings.py`).

## How to find it

1.  `grep_code` for secret-shaped assignments:

- `(?i)(api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|cookie[_-]?secret|jwt[_-]?secret|signing[_-]?key)\s*[:=]\s*['"][^'"]+['"]`

1.  `grep_code` for high-entropy-looking string assignments:

- `[A-Za-z0-9+/]{32,}={0,2}` (base64-looking)
- `[A-Fa-f0-9]{32,}` (hex blob)

1.  For each hit, `read_code_window` and judge:

- Is the value an obvious placeholder (`changeme`, `xxxxxxxx`,
  `your-secret-here`)? Lower severity / consider FP.
- Is the value loaded from env (`process.env.X || 'literal'`)? The literal
  fallback is still a finding if the env is unset in prod.
- Is the value a real-looking secret pattern (long, mixed-case, base64-ish)?
  **Critical finding.**

## True-positive signals

- A field like `cookieSecret`, `jwtSecret`, `apiKey`, `dbPassword` has a
  non-empty string literal value in tracked source.
- A clearly-real key (looks like an AWS access key `AKIA...`, GitHub PAT
  `ghp_...`, etc.).
- An OAuth `client_secret` literal value in a config file.

## False-positive signals (do NOT flag)

- The literal is an obvious placeholder text (`"change-me"`, `"your-key-here"`,
  `"YOUR_API_KEY"`, all uppercase placeholder).
- The value is in a test fixture / spec file documented as a mock.
- The value is empty string `""` or `null`.
- The value is read from `process.env.X` / `os.getenv("X")` with no literal
  fallback.

## Output: severity guidance

- **Critical** for real-looking production secrets (AWS keys, prod DB passwords,
  OAuth secrets).
- **High** for cookie/JWT signing secrets with non-trivial values (session
  forgery possible if leaked).
- **Medium** for development/test placeholders that still leak naming
  conventions.

## Output: CWE

- `CWE-798` (Use of Hard-coded Credentials)
- `CWE-259` (Use of Hard-coded Password)
- `CWE-547` (Use of Hard-coded, Security-relevant Constants)

## Output: rule_id slug

- `ai.hardcoded-secret`
- `ai.hardcoded-cookie-secret`
- `ai.hardcoded-api-key`
