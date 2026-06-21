---
name: validate-xss
description: Validates suspected Cross-Site Scripting (XSS) vulnerabilities by synthesizing safe payloads and executing them inside the isolated sandbox.
when_to_apply: Enforced when a suspected XSS vulnerability (CWE-79) is triaged as a True Positive.
file_globs: ["*.js", "*.py", "*.html"]
---

# Cross-Site Scripting (XSS) Validation Playbook

This playbook guides the Validation Agent on how to dynamically verify suspected
Cross-Site Scripting (XSS) vulnerabilities safely within the isolated sandbox.

---

## 1. Adversarial Payload Synthesis

XSS occurs when user-controlled data is rendered into HTML templates or views
without proper contextual output encoding or sanitization.

### Dynamic Synthesis Rules

1.  **Safe HTML Injection Payloads:** Synthesize a safe HTML payload containing
    a distinct, non-malicious tag identifier to assert rendering:

- **Safe XSS Payload:** `<h1>VULN_XSS</h1>` or `<xss id="VULN_XSS">`

1.  **Constructing the payload:**

- If the target rendering template is:

    ```html
    <div>{{ user_input }}</div>
    ```

- Synthesize a validation script:
    1.  Invoke the template compiler/renderer or trigger the target route,
        passing `user_input = "<h1>VULN_XSS</h1>"`.
    1.  Capture the raw returned HTML output string inside the sandbox.

---

## 2. Verification & Assertion Logic

After executing the sandbox using `execute_in_sandbox`, inspect the returned
dictionary:

- **Vulnerability Confirmed (TRUE_POSITIVE):**
    - If the returned HTML response contains the raw, unescaped payload string
      **`<h1>VULN_XSS</h1>`** or **`<xss id="VULN_XSS">`**, the XSS is **100%
      validated** (proving that contextual autoescaping is disabled or
      bypassed).
- **Vulnerability Refuted (FALSE_POSITIVE):**
    - If the output returns safely encoded entity strings (such as
      `&lt;h1&gt;VULN_XSS&lt;/h1&gt;`), the browser will render this safely as a
      text literal, not as HTML. Mark as `validated: false`.

---

## 3. Remediation Standard

When proposing the remediation:

- **Enable Global Autoescaping:** Ensure the template engine is configured with
  `autoescape: true` (e.g., in Swig, Nunjucks, Jinja, etc.).
- **Use Safe Encoding Abstractions:** Replace unsafe rendering directives (like
  `{{ data | safe }}` or `innerHTML`) with standard HTML text nodes (like
  `{{ data }}` or `textContent`).
