---
name: weak-crypto-or-password-storage
description: Detects weak cryptographic primitives (MD5, SHA1, DES, ECB), insecure password storage (plaintext, unsalted hash), hardcoded keys
when_to_apply: Codebase handles passwords, sensitive PII (SSN, DOB, financial), or uses cryptography for confidentiality/integrity
file_globs: **/data/**, **/dao/**, **/models/**, **/auth/**, **/crypto/**, **/config/**
---

# Weak Crypto / Password Storage: Detection Procedure

## What this is

Either: passwords stored insecurely (plaintext, hashed without salt, hashed with
a fast hash like MD5/SHA1), OR sensitive data encrypted with broken/weak
primitives, OR encryption keys hardcoded in source. OWASP A2 (auth), A6
(sensitive data) / CWE-256, CWE-916, CWE-327, CWE-798.

## Where to look

1.  `data/user-dao.js`, `models/user.py`, `auth/` — anywhere passwords are
    created/checked.
1.  `data/profile-dao.js`, `crypto/`, files handling SSN/DOB/credit cards.
1.  `config/`, `.env*`, hardcoded "secret" strings.

## How to find it

### Weak password storage

1.  `grep_code` for password assignment without hashing:

- `password\s*[:=]\s*req\.body\.(password|pwd)` (storing as-is)
- `\.password\s*=\s*req\.`

1.  `grep_code` for weak hash usage on passwords:

- `md5\s*\(.*password|sha1\s*\(.*password`
- `crypto\.createHash\s*\(\s*['"](md5|sha1)['"]`
- `hashlib\.(md5|sha1)\s*\(.*password` (Python)

1.  `grep_code` for the absence of bcrypt/argon2/scrypt/PBKDF2 imports in the
    user-storage file.

### Weak encryption primitives

1.  `grep_code`:

- `createCipheriv\s*\(\s*['"](des|des-ecb|aes-128-ecb|aes-256-ecb)['"]`
- `MODE_ECB|AES\.MODE_ECB` (Python)
- `Cipher\.getInstance\s*\(['"]DES|AES/ECB` (Java)

1.  `grep_code` for hardcoded keys:

- `key\s*=\s*['"][A-Za-z0-9+/=]{16,}['"]`
- `secret\s*=\s*['"][^'"]{8,}['"]`

1.  For each, `read_code_window` to verify the value is hardcoded and used as a
    cryptographic key.

## True-positive signals

- Password assigned directly into a user document from `req.body.password` with
  no hashing.
- MD5/SHA1 used as the only password hash (no salt + iteration count).
- ECB mode encryption (always wrong for confidentiality).
- A `key`, `secret`, `cookieSecret` field with a real-looking value committed in
  source.

## False-positive signals (do NOT flag)

- MD5/SHA1 used for non-security purposes (e.g., cache keys, ETags, content
  fingerprints).
- Hardcoded value in a test/spec file or example config clearly labeled as such.
- Symmetric encryption with AES-GCM or AES-CBC + HMAC and a key from env var /
  KMS — that's fine.

## Output: severity guidance

- **Critical** for plaintext passwords or hardcoded production secrets.
- **High** for MD5/SHA1 password hashing without salt, ECB-mode encryption of
  PII.
- **Medium** for outdated-but-not-broken (e.g., SHA-256 unsalted, DES used for
  non-critical encoding).

## Output: CWE

- `CWE-256` (Plaintext Storage of Password)
- `CWE-916` (Use of Password Hash With Insufficient Computational Effort)
- `CWE-327` (Use of a Broken or Risky Cryptographic Algorithm)
- `CWE-798` (Use of Hard-coded Credentials)

## Output: rule_id slug

- `ai.plaintext-password-storage`
- `ai.weak-password-hash`
- `ai.weak-encryption-algorithm`
- `ai.hardcoded-crypto-key`
