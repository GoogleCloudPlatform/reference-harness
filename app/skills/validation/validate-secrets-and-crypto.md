---
name: validate-secrets-and-crypto
description: Validates suspected weak cryptography and hardcoded secrets vulnerabilities by executing them inside the isolated sandbox.
when_to_apply: Enforced when a suspected weak cryptography (CWE-327 / CWE-328) or hardcoded secrets is triaged as a True Positive.
file_globs: ["*.js", "*.py", "*.json"]
---

# Weak Cryptography & Hardcoded Secrets Validation Playbook

This playbook guides the Validation Agent on how to dynamically verify suspected
weak cryptography and secrets vulnerabilities safely within the isolated
sandbox.

---

## 1. Adversarial Payload Synthesis

Weak cryptography occurs when insecure hashing algorithms (like MD5 or SHA1) are
used to protect sensitive password or token records, or when private keys are
hardcoded in plaintext on the filesystem.

### Dynamic Synthesis Rules

1.  **Analyzing Hashing Signatures:** To validate weak cryptography:

- Synthesize a script executing the target's hashing function on a predictable
  word string (like `"admin"`).
- Capture the hex digest of the output.

1.  **Checking Hardcoded Keys reachability:**

- Synthesize a script reading the suspected configuration or credentials object
  and assert if the key is a plaintext string value rather than a reference to
  environment parameters.

---

## 2. Verification & Assertion Logic

After executing the sandbox using `execute_in_sandbox`, inspect the returned
dictionary:

- **Vulnerability Confirmed (TRUE_POSITIVE):**
    - **Weak Hashing:** If the captured hash digest precisely matches the MD5
      signature (`21232f297a57a5a743894a0e4a801fc3`) or SHA1 signature
      (`d033e22ae348aeb5660fc2140aec35850c4da997`) of the target input, the weak
      crypto is **100% validated**.
    - **Secrets:** If the plaintext key matches typical entropy signatures, the
      secret is validated.
- **Vulnerability Refuted (FALSE_POSITIVE):**
    - If the hashing algorithm utilizes strong salted iterations (like `bcrypt`
      or `argon2`), mark as `validated: false`.

---

## 3. Remediation Standard

When proposing the remediation:

- **Weak Hashing:** Require upgrading the password hashing library to `bcrypt`
  or `argon2id` with high-entropy work factors.
- **Hardcoded Secrets:** **Strictly forbid plaintext keys on filesystem**.
  Require loading keys at runtime from secure environment variables
  (`process.env` / `os.environ`) or secure secrets manager stores.
