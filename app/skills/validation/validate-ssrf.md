---
name: validate-ssrf
description: Validates suspected Server-Side Request Forgery (SSRF) vulnerabilities by synthesizing safe payloads and executing them inside the isolated sandbox.
when_to_apply: Enforced when a suspected SSRF (CWE-918) is triaged as a True Positive.
file_globs: ["*.js", "*.py", "*.java"]
---

# SSRF Validation Playbook

This playbook guides the Validation Agent on how to dynamically verify suspected
Server-Side Request Forgery (SSRF) vulnerabilities safely within the isolated
sandbox.

---

## 1. Adversarial Payload Synthesis

When user-supplied input reaches an outbound HTTP client query request sink
(like `needle.get()`, `urllib.request.urlopen()`, or `axios.get()`), you must
synthesize a safe exploit verification payload.

### Dynamic Synthesis Rules

1.  **Targeting the local Loopback Adapter:** Because the container runs under
    `--network none` (zero egress), dynamic requests to external domains will
    fail. However, dynamic requests to the **local loopback adapter**
    (`127.0.0.1` or `localhost`) are routed locally inside the container
    namespaces!
1.  **Constructing the payload:**

- If the target code is:

    ```javascript
    needle.get(req.query.url)
    ```

- Synthesize the validation script:
    1.  Start a temporary mock HTTP server inside the validation script on port
        `8081` returning the unique text `VULN_SSRF_REACHED`.
    1.  Call the target function with: `url = "http://127.0.0.1:8081/"`
    1.  Assert that the returned response body contains `VULN_SSRF_REACHED`.

---

## 2. Verification & Assertion Logic

After executing the sandbox using `execute_in_sandbox`, inspect the returned
dictionary:

- **Vulnerability Confirmed (TRUE_POSITIVE):**
    - If the output indicates that the local mock server was successfully hit
      and returned the text **`VULN_SSRF_REACHED`**, the SSRF is **100%
      validated**.
- **Vulnerability Refuted (FALSE_POSITIVE):**
    - If the HTTP request fails with a host resolution error or is blocked by an
      domain allowlist check, mark as `validated: false`.

---

## 3. Remediation Standard

When proposing the remediation:

- **Domain/IP Allowlisting:** Require validating all user-supplied hostnames
  against a strict allowlist of permitted external domains. Reject requests to
  arbitrary IP addresses or local subnets (`127.0.0.1`, `192.168.0.0/16`, etc.).
