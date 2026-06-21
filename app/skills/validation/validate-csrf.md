---
name: validate-csrf
description: Validates suspected Cross-Site Request Forgery (CSRF) vulnerabilities by synthesizing safe payloads and executing them inside the isolated sandbox.
when_to_apply: Enforced when a suspected CSRF vulnerability (CWE-352) is triaged as a True Positive.
file_globs: ["*.js", "*.py"]
---

# Cross-Site Request Forgery (CSRF) Validation Playbook

This playbook guides the Validation Agent on how to dynamically verify suspected
Cross-Site Request Forgery (CSRF) vulnerabilities safely within the isolated
sandbox.

---

## 1. Adversarial Payload Synthesis

A CSRF vulnerability occurs when state-changing HTTP POST, PUT, or DELETE
operations can be successfully executed by a user session without requiring
unique, cryptographic tokens validated by the server.

### Dynamic Synthesis Rules

1.  **Forging the transaction request:** To dynamically prove CSRF, you must
    simulate a request that triggers the state-changing transaction **without**
    providing a valid CSRF token.
1.  **Constructing the payload:**

- If the target route handler is:

    ```javascript
    app.post("/profile/update", (req, res) => {
        db.updateEmail(req.session.userId, req.body.email);
        res.send("Updated");
    });
    ```

- Synthesize a validation script:
    1.  Mock a request session where the user is authenticated
        (`req.session.userId = "user_1"`).
    1.  Call the POST route passing the request body
        `email = "hacked@evil.com"`, strictly **omitting** any `_csrf` parameter
        or `X-CSRF-Token` headers.
    1.  Execute inside the sandbox.

---

## 2. Verification & Assertion Logic

After executing the sandbox using `execute_in_sandbox`, inspect the returned
dictionary:

- **Vulnerability Confirmed (TRUE_POSITIVE):**
    - If the request completes successfully (`exit_code == 0` or response is
      `200 OK`) and updates the profile mock parameters, the CSRF is **100%
      validated**.
- **Vulnerability Refuted (FALSE_POSITIVE):**
    - If the query is blocked with a `403 Forbidden` or `400 Bad Request`
      indicating missing or invalid CSRF tokens, mark as `validated: false`.

---

## 3. Remediation Standard

When proposing the remediation:

- **Require Standard CSRF Middleware:** Implement a robust, standard CSRF
  protection library (like `csurf` for Node.js, `flask-wtf` for Flask, or
  standard Spring Security CSRF guards) that validates cryptographical tokens on
  all state-changing requests.
