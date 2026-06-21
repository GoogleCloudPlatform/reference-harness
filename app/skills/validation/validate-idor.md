---
name: validate-idor
description: Validates suspected Insecure Direct Object Reference (IDOR) vulnerabilities by synthesizing safe payloads and executing them inside the isolated sandbox.
when_to_apply: Enforced when a suspected IDOR (CWE-639) is triaged as a True Positive.
file_globs: ["*.js", "*.py"]
---

# IDOR Validation Playbook

This playbook guides the Validation Agent on how to dynamically verify suspected
Insecure Direct Object Reference (IDOR) vulnerabilities safely within the
isolated sandbox.

---

## 1. Adversarial Payload Synthesis

An IDOR occurs when a route handler retrieves database records using an
unvalidated parameter (like a URL user ID `req.params.userId` or record ID
`req.query.id`) instead of enforcing the authenticated session's ownership
credentials.

### Dynamic Synthesis Rules

1.  **Simulating Parameter Mismatch:** To dynamically prove an IDOR, your
    validation payload must simulate a request where the parameter ID belongs to
    a **different user** than the active authenticated session ID.
1.  **Constructing the payload:**

- If the target route handler is:

    ```javascript
    app.get("/allocations/:userId", (req, res) => {
        db.fetchAllocations(req.params.userId, (data) => res.json(data));
    });
    ```

- Synthesize a validation script:
    1.  Mock a request session where `req.session.userId = "user_1"` (the
        authenticated attacker).
    1.  Mock the request parameters where `req.params.userId = "user_2"` (the
        victim).
    1.  Execute the handler inside the sandbox and assert that the returned
        allocations belong to `user_2`.

---

## 2. Verification & Assertion Logic

After executing the sandbox using `execute_in_sandbox`, inspect the returned
dictionary:

- **Vulnerability Confirmed (TRUE_POSITIVE):**
    - If the handler successfully returns the allocations of `user_2` (the
      victim) to the authenticated session of `user_1` (the attacker), the IDOR
      is **100% validated**.
- **Vulnerability Refuted (FALSE_POSITIVE):**
    - If the handler throws an access authorization error or checks that
      `req.params.userId == req.session.userId` before fetching, mark as
      `validated: false`.

---

## 3. Remediation Standard

When proposing the remediation:

- **Force Session-Based Lookups:** Modify the route handler to retrieve the key
  ID strictly from the authenticated server-side session object (e.g.
  `const userId = req.session.userId;`) instead of trusting the user-controlled
  URL parameter.
