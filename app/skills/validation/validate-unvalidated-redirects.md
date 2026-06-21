---
name: validate-unvalidated-redirects
description: Validates suspected Unvalidated Redirects (Open Redirects) vulnerabilities by synthesizing safe payloads and executing them inside the isolated sandbox.
when_to_apply: Enforced when a suspected Unvalidated Redirect (CWE-601) is triaged as a True Positive.
file_globs: ["*.js", "*.py"]
---

# Unvalidated Redirects (Open Redirects) Validation Playbook

This playbook guides the Validation Agent on how to dynamically verify suspected
Unvalidated Redirect vulnerabilities safely within the isolated sandbox.

---

## 1. Adversarial Payload Synthesis

An Open Redirect occurs when user-supplied input is passed directly to an HTTP
redirection sink (like `res.redirect()` or `redirect()`), allowing attackers to
redirect users to arbitrary external domains.

### Dynamic Synthesis Rules

1.  **Targeting an Untrusted Domain:** To dynamically prove an open redirect,
    synthesize a parameter string containing a highly recognizable external URL.
1.  **Constructing the payload:**

- If the target code is:

    ```javascript
    res.redirect(req.query.next)
    ```

- Synthesize a validation script:
    1.  Call the redirect handler passing the query parameter
        `next = "http://attacker.com"`.
    1.  Execute inside the sandbox.

---

## 2. Verification & Assertion Logic

After executing the sandbox using `execute_in_sandbox`, inspect the returned
dictionary:

- **Vulnerability Confirmed (TRUE_POSITIVE):**
    - If the returned response sets an HTTP status code of `301` or `302` and
      sets the `Location` header precisely to **`http://attacker.com`**, the
      open redirect is **100% validated**.
- **Vulnerability Refuted (FALSE_POSITIVE):**
    - If the redirection fails or limits targets strictly to local path
      boundaries (e.g. prepending a slash `/` or filtering out protocols), mark
      as `validated: false`.

---

## 3. Remediation Standard

When proposing the remediation:

- **Base Directory Path Restricting:** Force the redirection path to be a
  relative path (such as matching a leading `/` and omitting `//` protocol
  scopes) or validate the domain against a strict allowlist of permitted hosts.
